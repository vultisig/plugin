package api

import (
	"encoding/hex"
	"encoding/json"
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
	"github.com/sirupsen/logrus"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/mobile-tss-lib/tss"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/sigutil"
	"github.com/vultisig/plugin/internal/tasks"
	"github.com/vultisig/plugin/internal/types"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func NewErrorResponse(message string) ErrorResponse {
	return ErrorResponse{
		Message: message,
	}
}

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
	if policy.PluginID.String() != req.PluginID {
		return fmt.Errorf("policy plugin ID mismatch")
	}

	if err := s.plugin.ValidateProposedTransactions(policy.ToPluginPolicyCreateUpdate(), []vtypes.PluginKeysignRequest{req}); err != nil {
		return fmt.Errorf("failed to validate transaction proposal: %w", err)
	}

	// Validate message hash matches transaction
	txHash, err := calculateTransactionHash(req.Transaction)
	if err != nil {
		return fmt.Errorf("fail to calculate transaction hash: %w", err)
	}
	if txHash != req.Messages[0].Hash {
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

	filePathName := vcommon.GetVaultBackupFilename(req.PublicKey, policy.PluginID.String())
	content, err := s.vaultStorage.GetVault(filePathName)
	if err != nil {
		wrappedErr := fmt.Errorf("fail to read file, err: %w", err)
		s.logger.Infof("fail to read file in SignPluginMessages, err: %v", err)
		s.logger.Error(wrappedErr)
		return wrappedErr
	}

	_, err = vcommon.DecryptVaultFromBackup(s.cfg.EncryptionSecret, content)
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
		asynq.NewTask(tasks.TypeKeySignDKLS, buf),
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
		return c.JSON(http.StatusBadRequest, NewErrorResponse("invalid policy ID"))
	}
	uPolicyID, err := uuid.Parse(policyID)
	if err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("failed to parse policy ID")
		return c.JSON(http.StatusBadRequest, NewErrorResponse("invalid policy ID"))
	}
	policy, err := s.policyService.GetPluginPolicy(c.Request().Context(), uPolicyID)
	if err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("fail to get policy from database")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to get policy"))
	}

	return c.JSON(http.StatusOK, policy)
}

func (s *Server) GetAllPluginPolicies(c echo.Context) error {
	publicKey := c.Request().Header.Get("public_key")
	if publicKey == "" {
		return c.JSON(http.StatusBadRequest, NewErrorResponse("missing required header: public_key"))
	}

	pluginID := c.Request().Header.Get("plugin_id")
	if pluginID == "" {
		return c.JSON(http.StatusBadRequest, NewErrorResponse("missing required header: plugin_id"))
	}

	policies, err := s.policyService.GetPluginPolicies(c.Request().Context(), vtypes.PluginID(pluginID), publicKey)
	if err != nil {
		s.logger.WithError(err).WithFields(
			logrus.Fields{
				"public_key": publicKey,
				"plugin_id":  pluginID,
			}).Error("failed to get policies")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to get policies"))
	}

	return c.JSON(http.StatusOK, policies)
}

func (s *Server) CreatePluginPolicy(c echo.Context) error {
	var policy vtypes.PluginPolicyCreateUpdate
	if err := c.Bind(&policy); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	// We re-init plugin as verification server doesn't have plugin defined

	if err := s.plugin.ValidatePluginPolicy(policy); err != nil {
		s.logger.WithError(err).Error("Failed to validate plugin policy")
		return c.JSON(http.StatusBadRequest, NewErrorResponse("failed to validate policy"))
	}

	if policy.ID.String() == "" {
		policy.ID = uuid.New()
	}

	if !s.verifyPolicySignature(policy.ToPluginPolicy(), false) {
		s.logger.Error("invalid policy signature")
		return c.JSON(http.StatusForbidden, NewErrorResponse("Invalid policy signature"))
	}

	newPolicy, err := s.policyService.CreatePolicy(c.Request().Context(), policy.ToPluginPolicy())
	if err != nil {
		s.logger.WithError(err).Error("Failed to create plugin policy")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to create policy"))
	}

	return c.JSON(http.StatusOK, newPolicy)
}

func (s *Server) UpdatePluginPolicyById(c echo.Context) error {
	var policy vtypes.PluginPolicyCreateUpdate
	if err := c.Bind(&policy); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	if err := s.plugin.ValidatePluginPolicy(policy); err != nil {
		s.logger.WithError(err).
			WithField("plugin_id", policy.PluginID).
			WithField("policy_id", policy.ID).
			Error("Failed to validate plugin policy")
		return c.JSON(http.StatusBadRequest, NewErrorResponse("failed to validate policy"))
	}

	if !s.verifyPolicySignature(policy.ToPluginPolicy(), true) {
		s.logger.Error("invalid policy signature")
		return c.JSON(http.StatusForbidden, NewErrorResponse("Invalid policy signature"))
	}

	updatedPolicy, err := s.policyService.UpdatePolicy(c.Request().Context(), policy.ToPluginPolicy())
	if err != nil {
		s.logger.WithError(err).Error("Failed to update plugin policy")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to update policy"))
	}

	return c.JSON(http.StatusOK, updatedPolicy)
}

func (s *Server) DeletePluginPolicyById(c echo.Context) error {
	var reqBody struct {
		Signature string `json:"signature"`
	}

	if err := c.Bind(&reqBody); err != nil {
		return c.JSON(http.StatusBadRequest, NewErrorResponse("fail to parse request"))
	}

	policyID := c.Param("policyId")
	if policyID == "" {
		return c.JSON(http.StatusBadRequest, NewErrorResponse("invalid policy ID"))
	}
	uPolicyID, err := uuid.Parse(policyID)
	if err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("Failed to parse policy ID")
		return c.JSON(http.StatusBadRequest, NewErrorResponse("invalid policy ID"))
	}
	policy, err := s.policyService.GetPluginPolicy(c.Request().Context(), uPolicyID)
	if err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("Failed to get plugin policy")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to get policy"))
	}

	// This is because we have different signature stored in the database.
	policy.Signature = reqBody.Signature

	if !s.verifyPolicySignature(policy, true) {
		return c.JSON(http.StatusForbidden, NewErrorResponse("Invalid policy signature"))
	}

	if err := s.policyService.DeletePolicy(c.Request().Context(), uPolicyID, reqBody.Signature); err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("Failed to delete plugin policy")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to delete policy"))
	}

	return c.NoContent(http.StatusNoContent)
}

func (s *Server) GetPolicySchema(c echo.Context) error {
	pluginID := c.Request().Header.Get("plugin_id") // this is a unique identifier; this won't be needed once the DCA and Payroll are separate services
	if pluginID == "" {
		return c.JSON(http.StatusBadRequest, NewErrorResponse("missing required header: plugin_id"))
	}

	// TODO: need to deal with both DCA and Payroll plugins
	keyPath := filepath.Join("plugin", pluginID, "dcaPluginUiSchema.json")
	jsonData, err := os.ReadFile(keyPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to read plugin schema"))
	}

	var data map[string]interface{}
	jsonErr := json.Unmarshal(jsonData, &data)
	if jsonErr != nil {
		s.logger.WithError(jsonErr).Error("Failed to parse plugin schema")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to parse plugin schema"))
	}
	return c.JSON(http.StatusOK, data)
}

func (s *Server) GetRecipeSpecification(c echo.Context) error {
	recipeSpec := s.plugin.GetRecipeSpecification()
	return c.JSON(http.StatusOK, &recipeSpec)
}

func (s *Server) GetPluginPolicyTransactionHistory(c echo.Context) error {
	policyID := c.Param("policyId")

	if policyID == "" {
		return c.JSON(http.StatusBadRequest, NewErrorResponse("invalid policy ID"))
	}

	policyHistory, err := s.policyService.GetPluginPolicyTransactionHistory(c.Request().Context(), policyID)
	if err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("Failed to get plugin policy transaction history")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to get policy transaction history"))
	}

	return c.JSON(http.StatusOK, policyHistory)
}

func (s *Server) verifyPolicySignature(policy vtypes.PluginPolicy, update bool) bool {
	msgBytes, err := policyToMessageHex(policy)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert policy to message hex")
		return false
	}

	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(policy.Signature, "0x"))
	if err != nil {
		s.logger.WithError(err).Error("Failed to decode signature bytes")
		return false
	}
	vault, err := s.getVault(policy.PublicKey, policy.PluginID.String())
	if err != nil {
		s.logger.WithError(err).Error("fail to get vault")
		return false
	}
	derivedPublicKey, err := tss.GetDerivedPubKey(vault.PublicKeyEcdsa, vault.HexChainCode, vcommon.Ethereum.GetDerivePath(), false)
	if err != nil {
		s.logger.WithError(err).Error("failed to get derived public key")
		return false
	}

	isVerified, err := sigutil.VerifyPolicySignature(derivedPublicKey, msgBytes, signatureBytes)
	if err != nil {
		s.logger.WithError(err).Error("Failed to verify signature")
		return false
	}
	return isVerified
}

func (s *Server) getVault(publicKeyECDSA, pluginId string) (*v1.Vault, error) {
	if len(s.cfg.EncryptionSecret) == 0 {
		return nil, fmt.Errorf("no encryption secret")
	}
	fileName := vcommon.GetVaultBackupFilename(publicKeyECDSA, pluginId)
	vaultContent, err := s.vaultStorage.GetVault(fileName)
	if err != nil {
		s.logger.WithError(err).Error("fail to get vault")
		return nil, fmt.Errorf("failed to get vault, err: %w", err)
	}

	v, err := vcommon.DecryptVaultFromBackup(s.cfg.EncryptionSecret, vaultContent)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault,err: %w", err)
	}
	return v, nil
}

func policyToMessageHex(policy vtypes.PluginPolicy) ([]byte, error) {
	delimiter := "*#*"
	fields := []string{
		policy.Recipe,
		policy.PublicKey,
		policy.PolicyVersion,
		policy.PluginVersion}
	for _, item := range fields {
		if strings.Contains(item, delimiter) {
			return nil, fmt.Errorf("invalid policy signature")
		}
	}
	result := strings.Join(fields, delimiter)
	return []byte(result), nil
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
