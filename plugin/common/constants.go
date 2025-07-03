package common

// ANY CONSTANTS THAT ARE USED IN MULTIPLE PLUGINS SHOULD BE DEFINED HERE. Like ERC20 ABI.

const Erc20ABI = `[{
    "name": "transfer",
    "type": "function",
    "inputs": [
        {"name": "recipient", "type": "address"},
        {"name": "amount", "type": "uint256"}
    ],
    "outputs": [{"name": "", "type": "bool"}]
}]`
