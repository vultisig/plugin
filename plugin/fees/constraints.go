package fees

const PLUGIN_TYPE = "fees"
const PLUGIN_ID = "vultisig-fees-feee"

// Task Definitions
const TypeFeeCollection = "fees:collection"

var ERC20_TRANSFER_GAS int = 65000 //typically the upper bound from an ERC20 transfer

// ABIS
// TODO abis here for uniswap if no fees are present
const erc20ABI = `[{
    "name": "transfer",
    "type": "function",
    "inputs": [
        {"name": "recipient", "type": "address"},
        {"name": "amount", "type": "uint256"}
    ],
    "outputs": [{"name": "", "type": "bool"}]
}]`
