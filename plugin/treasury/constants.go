package treasury

// Task Definitions
const TypeTreasuryLoad = "treasury:load"            // Load list of pending fees into the db from the verifier
const TypeTreasuryTransact = "treasury:transaction" // Collect a list of loaded fees from the users wallet
const TypeTreasuryPostTx = "treasury:post_tx"       // Check the status of the fee runs

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
