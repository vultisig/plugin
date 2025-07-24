package copytrader

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/sirupsen/logrus"
)

func (p *Plugin) WatchSwap(ctx context.Context) {
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

				for _, tx := range block.Transactions() {
					// is Uniswap tx check
					if tx.To().String() == UniswapV2RouterAddress {
						txReceipt, err := p.ethRpc.TransactionReceipt(ctx, tx.Hash())
						if err != nil {
							p.logger.WithError(err).Error("failed to get block")
							continue
						}

						for _, log := range txReceipt.Logs {
							if log.Topics[0] == UniswapSwapTopic {
								signer := types.LatestSignerForChainID(tx.ChainId())
								sender, err := signer.Sender(tx)
								if err != nil {
									p.logger.WithError(err).Error("failed to get signer")
									continue
								}
								p.logger.WithFields(logrus.Fields{
									"sender": sender.String(),
									"txHash": tx.Hash().String(),
									"pair":   log.Address.String(),
								})
								//TODO: Trigger swaps there
							}
						}
					}
				}
			}
		}
	}
}
