package copytrader

import (
	"math/big"

	common "github.com/ethereum/go-ethereum/common"
)

type SwapTask struct {
	Sender common.Address
	Path   []common.Address
	Amount *big.Int
}
