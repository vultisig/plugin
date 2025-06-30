package common

import (
	"math/big"

	gcommon "github.com/ethereum/go-ethereum/common"
)

// ANY CONSTANTS THAT ARE USED IN MULTIPLE PLUGINS SHOULD BE DEFINED HERE. Like ERC20 ABI, zero addresses.

var EthereumMainnetEvmChainID *big.Int = big.NewInt(1) // 1 is the chain id for Ethereum mainnet
var EthereumZeroAddress gcommon.Address = gcommon.HexToAddress("0x0000000000000000000000000000000000000000")

const Erc20ABI = `[{
    "name": "transfer",
    "type": "function",
    "inputs": [
        {"name": "recipient", "type": "address"},
        {"name": "amount", "type": "uint256"}
    ],
    "outputs": [{"name": "", "type": "bool"}]
}]`
