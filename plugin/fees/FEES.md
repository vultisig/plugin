# Fees plugin

The fees pluigin is responsible for collecting user based fees incurred from other plugins

## Overview

As this is a 2 part system, and the fees plugin works differently from other plugins. Here is an overview of the current architecture.

### Verifier

The verifier is responsible for tracking the fees which need to be collected. This is achieved by creating a `billing` record against each plugin policy. The `billing` record contains information which is encoded in the `FeePolicy` struct of the recipe that a user signs. There may be zero, one, or several fee policies, and hence `billing` records connected to a `plugin policy`.

When a new plugin policy is created this data is extracted, verified (against the `pricings` (definitions) table) and then inserted accordingly in the db. It is also synced to the plugin server and if it fails everything fails. The following types of `billing` record exist. They are all recorded as enums in the db and in the implementation

- `once` - **fully implemented** one billing record and one `fee` record are created on policy insert.
- `recurring` - **mostly implemented** the db views and code is there but there is no scheduled job to create the fee records at intervals.
- `tx` - **barely implemented** the enum types exist but the code to incur fees upon certain tx based transactions is not yet there.

#### Fee records

Each fee has a unique ID in the system and **must** be connected to a `billing` record. Several fees may share the same `billing` record in the cases of recurrent or tx based billing records. In the case of one time fees, the fee is incurred instantly on successful install, otherwise the fee creations will be handled via trigger. Fees are known to be collected successfully by the use of a `collected_at` attribute and the `charged_at` as being set as the date the fee was incurred which is pre-empted to be needed for audit purposes.

#### Tx signing

- *currently pending pr* - fee ids are passed along with a signing request which are used to verify that the amount being requested for a signature is the same.
- *current* - the system checks for all fees which are due to be collected and if the amount doesn't match it rejects a sign request.

The signing request from the plugin server to the verifier is parsed and put through the above checks if the `policy_id` is that of a fee plugin.

### Plugin

In the `v2` implementation there are 3 distinct processes for handling fees. 

`loading` - pulls in the fees from the verifier and assigns them to a `fee run` (more later)
`transaction` - iterates through each of the fee runs, builds transactions, sends them to the verifier to be signed and then broadcasts them
`post` - checks the sent transactions and if successful updates the verifier which marks a value as `collected_at` **pending pr** (at the same time a `treasury_ledger` table is appended to with the fees which go to a developer and vultisig.)

#### Fee Runs

A `fee run` is a logical grouping of fees. They have various states depending on their lifecycle. When loading fees if a fee is found which has not yet been transacted *and* there is a `pending` (aka draft) fee run then the fee is included with it. If no fee run is detected then a new fee run is created.

The db structure are different between verifier and plugin here due to a separation of concerns. Verifier needs to create fee entries, track their state across their lifecycle and handle treasury output from them. The plugin server simply needs to group them and track their ids and amounts.

### Detailed Workflow

#### 1. Fee Loading Process (`LoadFees`)

**Trigger**: Scheduled cron job (configurable interval, default: every 10 minutes)

**Process**:
1. Retrieves all fee policies from database
2. For each policy, queries verifier API for pending fees
3. Validates fee amounts and consistency
4. Creates or updates fee runs in `draft` status
5. Adds individual fees to fee runs
6. Uses semaphore for concurrent processing (configurable limit).
7. Will only run when one of the other 3 processes isn't running

**Key Features**:
- Concurrent processing with semaphore limiting
- Duplicate fee detection and prevention
- Automatic fee run creation and management
- Error handling and rollback capabilities

#### 2. Transaction Handling (`HandleTransactions`)

**Trigger**: Scheduled cron job (configurable interval, default: fridays weekly)

**Process**:
1. Retrieves all fee runs in `draft` status
2. For each valid fee run:
   - Generates Ethereum ERC20 USDC transfer transaction
   - Creates keysign request with transaction data
   - Initiates signing process through TSS
   - Broadcasts signed transaction to blockchain
   - Updates fee run status to `sent`

**Transaction Details**:
- **Token**: USDC (ERC20)
- **Chain**: Ethereum (chainId: 1)
- **Recipient**: Vultisig Treasury (resolved via magic constants)
- **Gas Limit**: 65,000 (typical ERC20 transfer upper bound)

#### 3. Post-Transaction Processing (`HandlePostTx`)

**Trigger**: Scheduled cron job (configurable interval, default: every 10 minutes)

**Process**:
1. Monitors all fee runs in `sent` status
2. Checks transaction receipts on blockchain
3. Validates confirmation count against configured threshold
4. Updates verifier with collection status
5. Marks fee runs as `completed` or `failed`

**Confirmation Logic**:
- Waits for configurable number of confirmations
- Handles transaction failures and rebroadcast scenarios
- Maintains state consistency between plugin and verifier

### Job Scheduling & Configuration

#### Asynq Task Types

1. **`fees:load`** - Fee loading from verifier
2. **`fees:transaction`** - Transaction creation and broadcasting  
3. **`fees:post_tx`** - Post-transaction status checking

#### Policy Validation

The system validates fee policies against strict criteria:

1. **Resource Validation**: Only `ethereum.erc20.transfer` operations allowed
2. **Recipient Validation**: Must use `VULTISIG_TREASURY` magic constant
3. **Amount Constraints**: Maximum fee amount enforcement
4. **Recipe Schema**: Validates against predefined recipe specification

#### Transaction Security

1. **Mutex Protection**: Prevents concurrent transaction operations
2. **Amount Verification**: Cross-validates amounts between verifier and plugin
3. **Signature Validation**: Uses TSS for secure transaction signing
4. **Rollback Mechanisms**: Database transactions ensure consistency

### API Integration

#### Verifier API Endpoints

1. **`GetPublicKeysFees(publicKey)`** - Retrieves pending fees for a vault
2. **`MarkFeeAsCollected(txHash, timestamp, feeIds...)`** - Marks fees as collected

### Monitoring & Observability

#### Logging Structure

All operations use structured logging with consistent field names:
- `publicKey`: Vault public key
- `feeId`/`feeIds`: Individual fee identifiers
- `runId`: Fee run identifier  
- `policyId`: Plugin policy identifier
- `tx_hash`: Blockchain transaction hash

### Implementation Status

#### Fully Implemented Features
- `once` billing type - Single fee collection on policy creation
- Fee loading and aggregation system
- ERC20 USDC transaction generation
- TSS-based transaction signing
- Post-transaction confirmation tracking
- Database schema and migrations

#### Partially Implemented Features  
- `recurring` billing type - Database structure exists, scheduling incomplete
- Transaction rebroadcast logic - Framework present, full implementation pending
- Failed transaction recovery - Basic structure, comprehensive handling needed

#### Future Enhancements
- `tx` billing type - Transaction-based fee collection
- Multi-token support beyond USDC
- Cross-chain fee collection capabilities
- Advanced retry and recovery mechanisms

