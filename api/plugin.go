package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/labstack/echo/v4"
	"github.com/vultisig/verifier/plugin"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/sigutil"
	"github.com/vultisig/plugin/internal/tasks"
	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/plugin/dca"
	"github.com/vultisig/plugin/plugin/payroll"
)

func (s *Server) SignPluginMessages(c echo.Context) error {
	s.logger.Debug("PLUGIN SERVER: SIGN MESSAGES")

	var req vtypes.PluginKeysignRequest
	if err := c.Bind(&req); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	// Plugin-specific validations
	if len(req.Messages) != 1 {
		return fmt.Errorf("plugin signing requires exactly one message hash, current: %d", len(req.Messages))
	}

	// Get policy from database
	policy, err := s.db.GetPluginPolicy(c.Request().Context(), req.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get policy from database: %w", err)
	}

	// Validate policy matches plugin
	if policy.PluginID != req.PluginID {
		return fmt.Errorf("policy plugin ID mismatch")
	}

	// We re-init plugin as verification server doesn't have plugin defined
	var plg plugin.Plugin
	plg, err = s.initializePlugin(policy.PluginType)
	if err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	if err := plg.ValidateProposedTransactions(policy, []vtypes.PluginKeysignRequest{req}); err != nil {
		return fmt.Errorf("failed to validate transaction proposal: %w", err)
	}

	// Validate message hash matches transaction
	txHash, err := calculateTransactionHash(req.Transaction)
	if err != nil {
		return fmt.Errorf("fail to calculate transaction hash: %w", err)
	}
	if txHash != req.Messages[0] {
		return fmt.Errorf("message hash does not match transaction hash. expected %s, got %s", txHash, req.Messages[0])
	}

	// Reuse existing signing logic
	result, err := s.redis.Get(c.Request().Context(), req.SessionID)
	if err == nil && result != "" {
		return c.NoContent(http.StatusOK)
	}

	if err := s.redis.Set(c.Request().Context(), req.SessionID, req.SessionID, 30*time.Minute); err != nil {
		s.logger.Errorf("fail to set session, err: %v", err)
	}

	filePathName := common.GetVaultBackupFilename(req.PublicKey)
	content, err := s.blockStorage.GetFile(filePathName)
	if err != nil {
		wrappedErr := fmt.Errorf("fail to read file, err: %w", err)
		s.logger.Infof("fail to read file in SignPluginMessages, err: %v", err)
		s.logger.Error(wrappedErr)
		return wrappedErr
	}

	_, err = common.DecryptVaultFromBackup(req.VaultPassword, content)
	if err != nil {
		return fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
	}

	req.Parties = []string{common.PluginPartyID, common.VerifierPartyID}

	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("fail to marshal to json, err: %w", err)
	}

	// TODO: check if this is relevant
	// check that tx is done only once per period
	// should we also copy the db to the vultiserver, so that it can be used by the vultiserver (and use scheduler.go)? or query the blockchain?

	txToSign, err := s.db.GetTransactionByHash(c.Request().Context(), txHash)
	if err != nil {
		s.logger.Errorf("Failed to get transaction by hash from database: %v", err)
		return fmt.Errorf("fail to get transaction by hash: %w", err)
	}

	s.logger.Debug("PLUGIN SERVER: KEYSIGN TASK")

	ti, err := s.client.EnqueueContext(c.Request().Context(),
		asynq.NewTask(tasks.TypeKeySign, buf),
		asynq.MaxRetry(0),
		asynq.Timeout(2*time.Minute),
		asynq.Retention(5*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))

	if err != nil {
		txToSign.Metadata["error"] = err.Error()
		if updateErr := s.db.UpdateTransactionStatus(c.Request().Context(), txToSign.ID, types.StatusSigningFailed, txToSign.Metadata); updateErr != nil {
			s.logger.Errorf("Failed to update transaction status: %v", updateErr)
		}
		return fmt.Errorf("fail to enqueue keysign task: %w", err)
	}

	txToSign.Metadata["task_id"] = ti.ID
	if err := s.db.UpdateTransactionStatus(c.Request().Context(), txToSign.ID, types.StatusSigned, txToSign.Metadata); err != nil {
		s.logger.Errorf("Failed to update transaction with task ID: %v", err)
	}

	s.logger.Infof("Created transaction history for tx from plugin: %s...", req.Transaction[:min(20, len(req.Transaction))])

	return c.JSON(http.StatusOK, ti.ID)
}

func (s *Server) GetPluginPolicyById(c echo.Context) error {
	policyID := c.Param("policyId")
	if policyID == "" {
		err := fmt.Errorf("policy ID is required")
		message := map[string]interface{}{
			"message": "failed to get policy",
			"error":   err.Error(),
		}
		s.logger.Error(err)

		return c.JSON(http.StatusBadRequest, message)
	}

	policy, err := s.policyService.GetPluginPolicy(c.Request().Context(), policyID)
	if err != nil {
		err = fmt.Errorf("failed to get policy: %w", err)
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to get policy: %s", policyID),
			"error":   err.Error(),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.JSON(http.StatusOK, policy)
}

func (s *Server) GetAllPluginPolicies(c echo.Context) error {
	publicKey := c.Request().Header.Get("public_key")
	if publicKey == "" {
		err := fmt.Errorf("missing required header: public_key")
		message := map[string]interface{}{
			"message": "failed to get policies",
			"error":   err.Error(),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusBadRequest, message)
	}

	pluginType := c.Request().Header.Get("plugin_type")
	if pluginType == "" {
		err := fmt.Errorf("missing required header: plugin_type")
		message := map[string]interface{}{
			"message": "failed to get policies",
			"error":   err.Error(),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusBadRequest, message)
	}

	policies, err := s.policyService.GetPluginPolicies(c.Request().Context(), publicKey, pluginType)
	if err != nil {
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to get policies for public_key: %s", publicKey),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.JSON(http.StatusOK, policies)
}

func (s *Server) CreatePluginPolicy(c echo.Context) error {
	var policy vtypes.PluginPolicy
	if err := c.Bind(&policy); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	// We re-init plugin as verification server doesn't have plugin defined

	var plg plugin.Plugin
	plg, err := s.initializePlugin(policy.PluginType)
	if err != nil {
		err = fmt.Errorf("failed to initialize plugin: %w", err)
		s.logger.Error(err)
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to initialize plugin: %s", policy.PluginType),
		}
		return c.JSON(http.StatusBadRequest, message)
	}

	if err := plg.ValidatePluginPolicy(policy); err != nil {
		if errors.Unwrap(err) != nil {
			err = fmt.Errorf("failed to validate policy: %w", err)
			s.logger.Error(err)
			message := map[string]interface{}{
				"message": "failed to validate policy",
			}
			return c.JSON(http.StatusBadRequest, message)
		}

		err = fmt.Errorf("failed to validate policy: %w", err)
		s.logger.Error(err)
		message := map[string]interface{}{
			"error":   err.Error(), // only if error is not wrapped
			"message": "failed to validate policy",
		}

		return c.JSON(http.StatusBadRequest, message)
	}

	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}

	if !s.verifyPolicySignature(policy, false) {
		s.logger.Error("invalid policy signature")
		message := map[string]interface{}{
			"message": "Authorization failed",
			"error":   "Invalid policy signature",
		}
		return c.JSON(http.StatusForbidden, message)
	}

	newPolicy, err := s.policyService.CreatePolicyWithSync(c.Request().Context(), policy)
	if err != nil {
		err = fmt.Errorf("failed to create plugin policy: %w", err)
		message := map[string]interface{}{
			"message": "failed to create policy",
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.JSON(http.StatusOK, newPolicy)
}

func (s *Server) UpdatePluginPolicyById(c echo.Context) error {
	var policy vtypes.PluginPolicy
	if err := c.Bind(&policy); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	// We re-init plugin as verification server doesn't have plugin defined
	var plg plugin.Plugin
	plg, err := s.initializePlugin(policy.PluginType)
	if err != nil {
		if errors.Unwrap(err) != nil {
			err = fmt.Errorf("failed to initialize plugin: %w", err)

			message := map[string]interface{}{
				"message": fmt.Sprintf("failed to initialize plugin: %s", policy.PluginType),
			}

			s.logger.Error(err)
			return c.JSON(http.StatusBadRequest, message)
		}

		err = fmt.Errorf("failed to initialize plugin: %w", err)

		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to initialize plugin: %s", policy.PluginType),
			"error":   err.Error(),
		}

		s.logger.Error(err)
		return c.JSON(http.StatusBadRequest, message)
	}

	if err := plg.ValidatePluginPolicy(policy); err != nil {
		if errors.Unwrap(err) != nil {
			err = fmt.Errorf("failed to validate policy: %w", err)
			s.logger.Error(err)
			message := map[string]interface{}{
				"message": fmt.Sprintf("failed to validate policy: %s", policy.ID),
			}
			return c.JSON(http.StatusBadRequest, message)
		}

		err = fmt.Errorf("failed to validate policy: %w", err)
		s.logger.Error(err)
		message := map[string]interface{}{
			"error":   err.Error(), // only if error is not wrapped
			"message": fmt.Sprintf("failed to validate policy: %s", policy.ID),
		}
		return c.JSON(http.StatusBadRequest, message)
	}

	if !s.verifyPolicySignature(policy, true) {
		s.logger.Error("invalid policy signature")
		message := map[string]interface{}{
			"message": "Authorization failed",
			"error":   "Invalid policy signature",
		}
		return c.JSON(http.StatusForbidden, message)
	}

	updatedPolicy, err := s.policyService.UpdatePolicyWithSync(c.Request().Context(), policy)
	if err != nil {
		err = fmt.Errorf("failed to update plugin policy: %w", err)
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to update policy: %s", policy.ID),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.JSON(http.StatusOK, updatedPolicy)
}

func (s *Server) DeletePluginPolicyById(c echo.Context) error {
	var reqBody struct {
		Signature string `json:"signature"`
	}

	if err := c.Bind(&reqBody); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	policyID := c.Param("policyId")
	if policyID == "" {
		err := fmt.Errorf("policy ID is required")
		message := map[string]interface{}{
			"message": "failed to delete policy",
			"error":   err.Error(),
		}
		s.logger.Error(err)

		return c.JSON(http.StatusBadRequest, message)
	}

	policy, err := s.policyService.GetPluginPolicy(c.Request().Context(), policyID)
	if err != nil {
		err = fmt.Errorf("failed to get policy: %w", err)
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to get policy: %s", policyID),
			"error":   err.Error(),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	// This is because we have different signature stored in the database.
	policy.Signature = reqBody.Signature

	if !s.verifyPolicySignature(policy, true) {
		s.logger.Error("invalid policy signature")
		message := map[string]interface{}{
			"message": "Authorization failed",
			"error":   "Invalid policy signature",
		}
		return c.JSON(http.StatusForbidden, message)
	}

	if err := s.policyService.DeletePolicyWithSync(c.Request().Context(), policyID, reqBody.Signature); err != nil {
		err = fmt.Errorf("failed to delete policy: %w", err)
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to delete policy: %s", policyID),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.NoContent(http.StatusNoContent)
}

func (s *Server) GetPolicySchema(c echo.Context) error {
	pluginType := c.Request().Header.Get("plugin_type") // this is a unique identifier; this won't be needed once the DCA and Payroll are separate services
	if pluginType == "" {
		err := fmt.Errorf("missing required header: plugin_type")
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to get policy schema for plugin: %s", pluginType),
			"error":   err.Error(),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusBadRequest, message)
	}

	keyPath := filepath.Join("plugin", pluginType, "dcaPluginUiSchema.json")

	jsonData, err := os.ReadFile(keyPath)
	if err != nil {
		message := map[string]interface{}{
			"message": fmt.Sprintf("missing schema for plugin: %s", pluginType),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusBadRequest, message)
	}

	var data map[string]interface{}
	jsonErr := json.Unmarshal([]byte(jsonData), &data)
	if jsonErr != nil {

		message := map[string]interface{}{
			"message": fmt.Sprintf("could not unmarshal json: %s", jsonErr),
			"error":   jsonErr.Error(),
		}
		s.logger.Error(jsonErr)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.JSON(http.StatusOK, data)
}

func (s *Server) GetPluginPolicyTransactionHistory(c echo.Context) error {
	policyID := c.Param("policyId")

	if policyID == "" {
		err := fmt.Errorf("policy ID is required")
		message := map[string]interface{}{
			"message": "failed to get policy",
			"error":   err.Error(),
		}
		return c.JSON(http.StatusBadRequest, message)
	}

	policyHistory, err := s.policyService.GetPluginPolicyTransactionHistory(c.Request().Context(), policyID)
	if err != nil {
		err = fmt.Errorf("failed to get policy history: %w", err)
		message := map[string]interface{}{
			"message": fmt.Sprintf("failed to get policy history: %s", policyID),
		}
		s.logger.Error(err)
		return c.JSON(http.StatusInternalServerError, message)
	}

	return c.JSON(http.StatusOK, policyHistory)
}

func (s *Server) initializePlugin(pluginType string) (plugin.Plugin, error) {
	switch pluginType {
	case "payroll":
		return payroll.NewPayrollPlugin(s.db, s.logger, s.pluginConfigs["payroll"])
	case "dca":
		return dca.NewDCAPlugin(s.db, s.logger, s.pluginConfigs["dca"])
	default:
		return nil, fmt.Errorf("unknown plugin type: %s", pluginType)
	}
}
func (s *Server) verifyPolicySignature(policy vtypes.PluginPolicy, update bool) bool {
	msgHex, err := policyToMessageHex(policy, update)
	if err != nil {
		s.logger.Error(fmt.Errorf("failed to convert policy to message hex: %w", err))
		return false
	}

	msgBytes, err := hex.DecodeString(strings.TrimPrefix(msgHex, "0x"))
	if err != nil {
		s.logger.Error(fmt.Errorf("failed to decode message bytes: %w", err))
		return false
	}

	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(policy.Signature, "0x"))
	if err != nil {
		s.logger.Error(fmt.Errorf("failed to decode signature bytes: %w", err))
		return false
	}

	isVerified, err := sigutil.VerifySignature(policy.PublicKey, policy.ChainCodeHex, msgBytes, signatureBytes)
	if err != nil {
		s.logger.Error(fmt.Errorf("failed to verify signature: %w", err))
		return false
	}
	return isVerified
}

func policyToMessageHex(policy vtypes.PluginPolicy, isUpdate bool) (string, error) {
	if !isUpdate {
		policy.ID = ""
	}
	// signature is not part of the message that is signed
	policy.Signature = ""

	serializedPolicy, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to serialize policy")
	}
	return hex.EncodeToString(serializedPolicy), nil
}

func calculateTransactionHash(txData string) (string, error) {
	tx := &gtypes.Transaction{}
	rawTx, err := hex.DecodeString(txData)
	if err != nil {
		return "", fmt.Errorf("invalid transaction hex: %w", err)
	}

	err = tx.UnmarshalBinary(rawTx)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	chainID := tx.ChainId()
	signer := gtypes.NewEIP155Signer(chainID)
	hash := signer.Hash(tx).String()[2:]
	return hash, nil
}
