package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"github.com/vultisig/mobile-tss-lib/tss"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/sigutil"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func NewErrorResponse(message string) ErrorResponse {
	return ErrorResponse{
		Message: message,
	}
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

	policies, err := s.policyService.GetPluginPolicies(c.Request().Context(), vtypes.PluginID(pluginID), publicKey, true)
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
	var policy vtypes.PluginPolicy
	if err := c.Bind(&policy); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}

	// We re-init plugin as verification server doesn't have plugin defined

	if err := s.plugin.ValidatePluginPolicy(policy); err != nil {
		s.logger.WithError(err).Error("failed to validate plugin policy")
		return c.JSON(http.StatusBadRequest, NewErrorResponse("failed to validate policy"))
	}

	if policy.ID.String() == "" {
		policy.ID = uuid.New()
	}

	if !s.verifyPolicySignature(policy) {
		s.logger.Error("invalid policy signature")
		return c.JSON(http.StatusForbidden, NewErrorResponse("Invalid policy signature"))
	}

	newPolicy, err := s.policyService.CreatePolicy(c.Request().Context(), policy)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create plugin policy")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to create policy"))
	}

	return c.JSON(http.StatusOK, newPolicy)
}

func (s *Server) UpdatePluginPolicyById(c echo.Context) error {
	var policy vtypes.PluginPolicy
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

	if !s.verifyPolicySignature(policy) {
		s.logger.Error("invalid policy signature")
		return c.JSON(http.StatusForbidden, NewErrorResponse("Invalid policy signature"))
	}

	updatedPolicy, err := s.policyService.UpdatePolicy(c.Request().Context(), policy)
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

	if !s.verifyPolicySignature(*policy) {
		return c.JSON(http.StatusForbidden, NewErrorResponse("Invalid policy signature"))
	}

	if err := s.policyService.DeletePolicy(c.Request().Context(), uPolicyID, reqBody.Signature); err != nil {
		s.logger.WithError(err).
			WithField("policy_id", policyID).
			Error("Failed to delete plugin policy")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to delete policy"))
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"policy_id": policyID,
	})
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
	recipeSpec, err := s.plugin.GetRecipeSpecification()
	if err != nil {
		s.logger.WithError(err).Error("Failed to get recipe spec")
		return c.JSON(http.StatusInternalServerError, NewErrorResponse("failed to get recipe spec"))
	}
	return c.JSON(http.StatusOK, recipeSpec)
}

func (s *Server) verifyPolicySignature(policy vtypes.PluginPolicy) bool {
	msgBytes, err := common.PolicyToMessageHex(policy)
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
