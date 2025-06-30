package common

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	gcommon "github.com/ethereum/go-ethereum/common"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	reth "github.com/vultisig/recipes/ethereum"
	vcommon "github.com/vultisig/verifier/common"
	"golang.org/x/sync/errgroup"
)

// DEFINE COMMON PLUGIN FUNCTIONS HERE (eg creating an unsigned erc20 transaction)

// Creates an unsigned ERC20 transaction
func GenUnsignedTx(
	ctx context.Context,
	chain vcommon.Chain,
	senderAddress, tokenID, amount, to string,
	rpcClient *ethclient.Client,
	nonce uint64,
) ([]byte, error) {
	switch chain {
	case vcommon.Ethereum:
		tx, err := EvmMakeUnsignedTransfer(
			ctx,
			EthereumMainnetEvmChainID,
			senderAddress,
			tokenID,
			amount,
			to,
			rpcClient,
			nonce,
		)
		if err != nil {
			return nil, fmt.Errorf("p.evmMakeUnsignedTransfer: %v", err)
		}
		return tx, nil
	default:
		return nil, fmt.Errorf("unsupported chain: %s", chain)
	}
}

func EvmMakeUnsignedTransfer(
	ctx context.Context,
	evmChainID *big.Int,
	senderAddress, tokenIDStr, amountStr, toStr string,
	rpcClient *ethclient.Client,
	nonce uint64,
) ([]byte, error) {
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, fmt.Errorf("new(big.Int).SetString: %s", amountStr)
	}

	to := gcommon.HexToAddress(toStr)
	tokenID := gcommon.HexToAddress(tokenIDStr)

	var (
		value *big.Int
		data  []byte
	)
	if tokenID == EthereumZeroAddress {
		value = amount
		data = nil
	} else {
		parsedABI, err := abi.JSON(strings.NewReader(Erc20ABI))
		if err != nil {
			return nil, fmt.Errorf("abi.JSON(strings.NewReader(erc20ABI)): %v", err)
		}

		d, err := parsedABI.Pack("transfer", to, amount)
		if err != nil {
			return nil, fmt.Errorf("parsedABI.Pack: %v", err)
		}
		value = big.NewInt(0)
		data = d
	}

	senderAddressHex := gcommon.HexToAddress(senderAddress)

	nonce, gasLimit, gasTipCap, maxFeePerGas, accessList, err := EvmEstimateTx(
		ctx,
		senderAddressHex,
		tokenID,
		value,
		data,
		rpcClient,
		nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("p.evmEstimateTx: %v", err)
	}

	bytes, err := EvmEncodeUnsignedDynamicFeeTx(
		evmChainID,
		nonce,
		tokenID,
		gasTipCap,
		maxFeePerGas,
		gasLimit,
		value,
		data,
		accessList,
	)
	if err != nil {
		return nil, fmt.Errorf("evmEncodeUnsignedDynamicFeeTx: %v", err)
	}
	return bytes, nil
}

func EvmEstimateTx(
	ctx context.Context,
	from, to gcommon.Address,
	value *big.Int,
	data []byte,
	rpcClient *ethclient.Client,
	nonce uint64,
) (uint64, uint64, *big.Int, *big.Int, gtypes.AccessList, error) {
	var eg errgroup.Group
	var gasLimit uint64
	eg.Go(func() error {
		r, e := rpcClient.EstimateGas(ctx, ethereum.CallMsg{
			From:  from,
			To:    &to,
			Data:  data,
			Value: value,
		})
		if e != nil {
			return fmt.Errorf("p.rpcClient.EstimateGas: %v", e)
		}
		gasLimit = r
		return nil
	})

	var gasTipCap *big.Int
	eg.Go(func() error {
		r, e := rpcClient.SuggestGasTipCap(ctx)
		if e != nil {
			return fmt.Errorf("p.rpcClient.SuggestGasTipCap: %v", e)
		}
		gasTipCap = r
		return nil
	})

	var baseFee *big.Int
	eg.Go(func() error {
		feeHistory, e := rpcClient.FeeHistory(ctx, 1, nil, nil)
		if e != nil {
			return fmt.Errorf("p.rpcClient.FeeHistory: %v", e)
		}
		if len(feeHistory.BaseFee) == 0 {
			return fmt.Errorf("feeHistory.BaseFee is empty")
		}
		baseFee = feeHistory.BaseFee[0]
		return nil
	})

	err := eg.Wait()
	if err != nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("eg.Wait: %v", err)
	}

	maxFeePerGas := new(big.Int).Add(gasTipCap, baseFee)

	type createAccessListArgs struct {
		From                 string `json:"from,omitempty"`
		To                   string `json:"to,omitempty"`
		Gas                  string `json:"gas,omitempty"`
		GasPrice             string `json:"gasPrice,omitempty"`
		MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"`
		MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`
		Value                string `json:"value,omitempty"`
		Data                 string `json:"data,omitempty"`
	}
	createAccessListRes := struct {
		AccessList gtypes.AccessList `json:"accessList"`
		GasUsed    string            `json:"gasUsed"`
	}{}
	err = rpcClient.Client().CallContext(
		ctx,
		&createAccessListRes,
		"eth_createAccessList",
		[]interface{}{
			createAccessListArgs{
				From:                 from.Hex(),
				To:                   to.Hex(),
				Gas:                  "0x" + strconv.FormatUint(gasLimit, 16),
				MaxPriorityFeePerGas: "0x" + gcommon.Bytes2Hex(gasTipCap.Bytes()),
				MaxFeePerGas:         "0x" + gcommon.Bytes2Hex(maxFeePerGas.Bytes()),
				Value:                "0x" + gcommon.Bytes2Hex(value.Bytes()),
				Data:                 "0x" + gcommon.Bytes2Hex(data),
			},
			"latest",
		},
	)
	if err != nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("p.rpcClient.Client().CallContext: %v", err)
	}

	return nonce, gasLimit, gasTipCap, maxFeePerGas, createAccessListRes.AccessList, nil
}

func EvmEncodeUnsignedDynamicFeeTx(
	evmChainID *big.Int,
	nonce uint64,
	to gcommon.Address,
	maxPriorityFeePerGas, maxFeePerGas *big.Int,
	gas uint64,
	value *big.Int,
	data []byte,
	accessList gtypes.AccessList,
) ([]byte, error) {
	bytes, err := rlp.EncodeToBytes(reth.DynamicFeeTxWithoutSignature{
		ChainID:    evmChainID,
		Nonce:      nonce,
		GasTipCap:  maxPriorityFeePerGas,
		GasFeeCap:  maxFeePerGas,
		Gas:        gas,
		To:         &to,
		Value:      value,
		Data:       data,
		AccessList: accessList,
	})
	if err != nil {
		return nil, fmt.Errorf("rlp.EncodeToBytes: %v", err)
	}

	res := append([]byte{gtypes.DynamicFeeTxType}, bytes...)
	return res, nil
}
