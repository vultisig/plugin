package fees

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/google/uuid"
	"github.com/vultisig/plugin/common"
	reth "github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"
)

func getHash(inTx evm.UnsignedTx, r, s, v []byte, chainID *big.Int) (*etypes.Transaction, error) {
	var sig []byte
	sig = append(sig, r...)
	sig = append(sig, s...)
	sig = append(sig, v...)

	inTxDecoded, err := reth.DecodeUnsignedPayload(inTx)
	if err != nil {
		return nil, fmt.Errorf("reth.DecodeUnsignedPayload: %w", err)
	}

	outTx, err := etypes.NewTx(inTxDecoded).WithSignature(etypes.LatestSignerForChainID(chainID), sig)
	if err != nil {
		return nil, fmt.Errorf("types.NewTx.WithSignature: %w", err)
	}

	return outTx, nil
}

type erc20Data struct {
	to     ecommon.Address `json:"to"`
	amount *big.Int        `json:"amount"`
	token  ecommon.Address `json:"token"`
}

type unsignedDynamicFeeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *ecommon.Address
	Value      *big.Int
	Data       []byte
	AccessList etypes.AccessList
}

func decodeUnsignedTx(rawHex string) (*unsignedDynamicFeeTx, error) {
	rawHex = strings.TrimPrefix(rawHex, "0x")
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}

	if len(rawBytes) == 0 || rawBytes[0] != 0x02 {
		return nil, fmt.Errorf("unsupported transaction type: 0x%02x", rawBytes[0])
	}

	// Decode RLP (strip type byte)
	tx := new(unsignedDynamicFeeTx)
	if err := rlp.DecodeBytes(rawBytes[1:], tx); err != nil {
		return nil, fmt.Errorf("rlp decode failed: %w", err)
	}

	return tx, nil
}

// pass in a types.Transaction or a unsignedDynamicFeeTx
func parseErc20Tx[T any](transaction T) (*erc20Data, error) {
	// Decode ERC20 transfer ABI
	const transferABI = `[{"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(transferABI))

	var data []byte
	var to *ecommon.Address

	switch tx := any(transaction).(type) {
	case *etypes.Transaction:
		data = tx.Data()
		to = tx.To()
	case *unsignedDynamicFeeTx:
		data = tx.Data
		to = tx.To
	default:
		return nil, fmt.Errorf("unsupported transaction struct type")
	}

	method, err := parsedABI.MethodById(data[:4])
	if err != nil {
		return nil, fmt.Errorf("unknown method ID")
	}

	args := make(map[string]interface{})
	if err := method.Inputs.UnpackIntoMap(args, data[4:]); err != nil {
		return nil, fmt.Errorf("failed to unpack args")
	}

	recipient, ok := args["to"].(ecommon.Address)
	if !ok {
		return nil, fmt.Errorf("invalid recipient type")
	}
	amount, ok := args["value"].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid amount type")
	}

	return &erc20Data{
		to:     recipient,
		amount: amount,
		token:  *to,
	}, nil
}

func hexutilDecode(hexStr string) ([]byte, error) {
	if !strings.HasPrefix(hexStr, "0x") {
		hexStr = "0x" + hexStr
	}
	return hexutil.Decode(hexStr)
}

func appendSignature(inTx evm.UnsignedTx, r, s, v []byte, chainID *big.Int) (*etypes.Transaction, error) {
	var sig []byte
	sig = append(sig, r...)
	sig = append(sig, s...)
	sig = append(sig, v...)

	inTxDecoded, err := reth.DecodeUnsignedPayload(inTx)
	if err != nil {
		return nil, fmt.Errorf("reth.DecodeUnsignedPayload: %w", err)
	}

	outTx, err := etypes.NewTx(inTxDecoded).WithSignature(etypes.LatestSignerForChainID(chainID), sig)
	if err != nil {
		return nil, fmt.Errorf("types.NewTx.WithSignature: %w", err)
	}

	return outTx, nil
}

func (fp *FeePlugin) getEthAddressFromFeePolicy(policy vtypes.PluginPolicy) (string, error) {
	vault, err := common.GetVaultFromPolicy(fp.vaultStorage, policy, fp.encryptionSecret)
	if err != nil {
		return "", fmt.Errorf("failed to get vault from policy: %v", err)
	}

	// Get the ethereum derived addresses from the vaults master public key
	fromAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vcommon.Ethereum)
	if err != nil {
		return "", fmt.Errorf("failed to get eth address: %v", err)
	}

	return fromAddress, nil
}

func (fp *FeePlugin) getEthAddressFromFeePolicyId(policyId uuid.UUID) (string, error) {
	policy, err := fp.db.GetPluginPolicy(context.Background(), policyId)
	if err != nil {
		return "", fmt.Errorf("failed to get policy: %v", err)
	}
	return fp.getEthAddressFromFeePolicy(*policy)
}
