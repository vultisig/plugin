package common

import (
	"fmt"

	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	vtypes "github.com/vultisig/verifier/types"
	vault "github.com/vultisig/verifier/vault"
	vgcommon "github.com/vultisig/vultisig-go/common"
)

func GetVaultFromPolicy(s vault.Storage, policy vtypes.PluginPolicy, encryptionSecret string) (*v1.Vault, error) {
	vaultFileName := vgcommon.GetVaultBackupFilename(policy.PublicKey, policy.PluginID.String())
	vaultContent, err := s.GetVault(vaultFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault")
	}

	if vaultContent == nil {
		return nil, fmt.Errorf("vault not found")
	}

	return vgcommon.DecryptVaultFromBackup(encryptionSecret, vaultContent)
}
