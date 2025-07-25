package copytrader

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/vultisig/recipes/sdk/evm/codegen/uniswapv2_router"
)

func (p *Plugin) WatchSwap(ctx context.Context) {
	var uniswapABI abi.ABI
	err := json.Unmarshal([]byte(uniswapv2_router.Uniswapv2RouterMetaData.ABI), &uniswapABI)
	if err != nil {
		panic(err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			currentBlock, err := p.ethRpc.BlockNumber(ctx)
			if err != nil {
				p.logger.WithError(err).Error("failed to get block")
				continue
			}

			for p.blockID < currentBlock {
				p.blockID++
				p.logger.Info("Processing block: ", p.blockID)

				block, err := p.ethRpc.BlockByNumber(ctx, big.NewInt(0).SetUint64(p.blockID))
				if err != nil {
					p.logger.WithError(err).Error("failed to get block")
					continue
				}

				// Process txs to find UniswapV2Router interactions
				for _, tx := range block.Transactions() {
					if tx.To() == nil {
						continue
					}
					// is Uniswap tx check
					if tx.To().String() == UniswapV2RouterAddress {
						inputBytes := tx.Data()
						signature, data := inputBytes[:4], inputBytes[4:]
						if hex.EncodeToString(signature) != SwapExactTokensForTokens {
							continue
						}

						method, err := uniswapABI.MethodById(signature)
						if err != nil {
							p.logger.WithError(err).Error("unknown method")
							continue
						}

						// Getting args from tx to find necessary info
						var args = make(map[string]interface{})
						err = method.Inputs.UnpackIntoMap(args, data)
						if err != nil {
							p.logger.WithError(err).Error("failed to unpack data")
							continue
						}

						path := args["path"]
						tokens, valid := path.([]common.Address)
						if !valid {
							p.logger.Error("invalid path", path)
							continue
						}

						amountIn, _ := new(big.Int).SetString(fmt.Sprint(args["amountIn"]), 10)
						to := args["to"]
						sender, valid := to.(common.Address)
						if !valid {
							p.logger.Error("invalid sender", to)
							continue
						}

						//Triggering swaps
						fmt.Println("sender", sender.String())
						fmt.Println("amount", amountIn.String())
						fmt.Println("path: ", tokens)
					}
				}
			}
		}
	}
}
