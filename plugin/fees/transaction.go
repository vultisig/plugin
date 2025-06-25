package fees

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"
)

func (fp *FeePlugin) buildUSDCEthFeeTransaction(ecdsaPublicKey string, feeIds []uuid.UUID, amount int) (vtypes.PluginKeysignRequest, error) {
	//TODO should amount be non negative
	// derivePath := common.Ethereum.GetDerivePath()
	erc20ABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to parse erc20 abi: %w", err)
	}

	vault, _ := fp.vaultStorage.GetVault("TODO FILENAME")

	//TODO wrong
	chainCode := string(vault)

	ethFromAddressString, _, _, err := address.GetAddress(ecdsaPublicKey, chainCode, vcommon.Ethereum)
	if err != nil {
		return vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to get eth from address: %w", err)
	}

	//TODO garry
	data, err := erc20ABI.Pack("transfer", fp.config.CollectorAddress)
	if err != nil {
		return vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to pack erc20 abi: %w", err)
	}

	ethFromAddress := ecommon.HexToAddress(ethFromAddressString)
	nonce, err := fp.rpcClient.PendingNonceAt(context.Background(), ethFromAddress)

	gasPrice, err := fp.rpcClient.SuggestGasPrice(context.Background())
	if err != nil {
		return vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to suggest gas price: %w", err)
	}

	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(int64(fp.config.Gas.PriceMultiplier)))

	tx := etypes.NewTransaction(nonce, ethFromAddress, big.NewInt(0), uint64(fp.config.Gas.LimitMultiplier*ERC20_TRANSFER_GAS), gasPrice, data)

	//TODO - partial work completed to here
	fmt.Println(tx)

	fp.Log(logrus.DebugLevel, "Building fee transaction for fee: ", feeIds)

	sessionID := uuid.New()

	return vtypes.PluginKeysignRequest{
		KeysignRequest: vtypes.KeysignRequest{
			PublicKey: ecdsaPublicKey,
			SessionID: sessionID.String(),
		},
	}, nil

}
