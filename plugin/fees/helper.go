package fees

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/vultisig/mobile-tss-lib/tss"
	reth "github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/sdk/evm"
	vtypes "github.com/vultisig/verifier/types"
)

func getTransaction(inTx evm.UnsignedTx, r, s, v []byte, chainID *big.Int) (*etypes.Transaction, error) {
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

func parseTransaction(rawTx string) (*etypes.Transaction, error) {
	txBytes := common.FromHex(rawTx)
	var tx etypes.Transaction
	if err := rlp.DecodeBytes(txBytes, &tx); err != nil {
		return nil, fmt.Errorf("rlp.DecodeBytes: %w", err)
	}
	return &tx, nil
}

type erc20tx struct {
	to     ecommon.Address `json:"to"`
	amount *big.Int        `json:"amount"`
	token  ecommon.Address `json:"token"`
}

func decodeTx(rawHex string) (*erc20tx, error) {
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

	rawHex = strings.TrimPrefix(rawHex, "0x")

	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}

	// Check transaction type (EIP-1559 is 0x02)
	if len(rawBytes) == 0 || rawBytes[0] != 0x02 {
		return nil, fmt.Errorf("unsupported transaction type: 0x%02x", rawBytes[0])
	}

	tx := new(unsignedDynamicFeeTx)
	err = rlp.DecodeBytes(rawBytes[1:], tx)
	if err != nil {
		return nil, fmt.Errorf("rlp decode failed: %w", err)
	}

	// Parse the ERC20 transfer ABI
	const transferABI = `[{"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]}]`
	parsedABI, err := abi.JSON(strings.NewReader(transferABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI")
	}

	// Get the method by selector
	method, err := parsedABI.MethodById(tx.Data[:4])
	if err != nil {
		return nil, fmt.Errorf("unknown method ID")
	}

	// Decode the arguments
	args := make(map[string]interface{})
	if err := method.Inputs.UnpackIntoMap(args, tx.Data[4:]); err != nil {
		return nil, fmt.Errorf("failed get recipient and amount from tx")
	}

	recipient, ok := args["to"].(ecommon.Address)
	if !ok {
		return nil, fmt.Errorf("invalid recipient address in tx data")
	}

	amount, ok := args["value"].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid amount in tx data")
	}

	return &erc20tx{
		to:     recipient,
		amount: amount,
		token:  *tx.To,
	}, nil
}

func hexutilDecode(hexStr string) ([]byte, error) {
	if !strings.HasPrefix(hexStr, "0x") {
		hexStr = "0x" + hexStr
	}
	return hexutil.Decode(hexStr)
}

// deprecated, use proposeTransactions instead as it relies on a fee run and a context
func (fp *FeePlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	return nil, errors.New("not implemented")
}

// deprecated, no longer part of the flow. initSign handles the transaction signing, sending and recording of initial state. The process thereafter is handled by the post_tx flow
func (fp *FeePlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	return fmt.Errorf("not implemented")
}
