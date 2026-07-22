# QCash

QCash is Paqus' bearer cash feature. It lets a user convert on-chain XPQ into
local `.XPQ` cash files, move those files outside the chain, and later deposit
them back into the ledger as on-chain balance.

## Summary

- **Withdraw cash**: converts on-chain XPQ into QCash outputs.
- **Cash file**: a local `.XPQ` file containing the secret required to redeem a
  QCash coin.
- **Deposit cash**: proves ownership of a cash file and credits an on-chain
  recipient.
- **The ledger is the source of truth**: a file can exist on disk, but only the
  ledger decides whether the coin is pending, spendable, or already spent.
- **QCash has maturity rules**: newly withdrawn cash cannot be deposited until
  it passes QCash maturity.

## Security Model

A cash file is a bearer asset. Anyone who holds an unspent, spendable `.XPQ`
file can deposit that coin.

Practical implications:

- Back up cash files carefully.
- Do not share `.XPQ` files unless you intentionally want to transfer cash.
- If a file is lost before deposit, the user loses access to that cash.
- If a file is stolen before deposit, the thief can deposit it first.

The ledger prevents double-spends. Once a cash coin is deposited, it is removed
from the QCash UTXO set and the old file can no longer be used.

## Lifecycle

### 1. Withdraw XPQ To Cash Files

The wallet creates a QCash `withdraw_cash` transaction, submits it to the node,
and writes `.XPQ` files locally.

Example:

```bash
cd Wallet
cargo run -- cash withdraw 100 --wallet ../Node/wallet.json --out ./cash
```

From the interactive wallet menu:

```text
QCash -> Withdraw XPQ to cash files
```

Cash file names use this format:

```text
<denomination>_<short_coin_id>.XPQ
```

Examples:

```text
20_B875F3464C15F087.XPQ
100_C91E1B3A98CDB3A8.XPQ
```

The file is written immediately because the wallet must preserve the bearer
secret when the withdraw transaction is created. That does not mean the coin is
immediately spendable.

### 2. Wait For Maturity

A QCash withdrawal must mature before it can be deposited. If a file is not
mature yet, deposit is rejected by ledger validation.

Check file status:

```bash
cargo run -- cash sync ./cash
```

Possible lifecycle statuses:

```text
ledger-pending      the withdraw is known but not mature yet
ready               the cash coin is spendable
spent-or-unissued   the coin is spent or unknown to the ledger
```

### 3. Deposit A Cash File

Deposit converts a cash file back into on-chain balance.

```bash
cargo run -- cash deposit ./cash/100_C91E1B3A98CDB3A8.XPQ \
  --to PX1...
```

From the interactive wallet menu:

```text
QCash -> Deposit cash file
```

A successful deposit creates a `deposit_cash` transaction. After confirmation,
the recipient receives an on-chain credit. That credit follows QCash deposit
maturity before it becomes fully spendable.

## Fees

QCash fees are based on transaction virtual size:

```text
fee = virtual_size * fee_rate
```

The wallet default is:

```text
1 paqus/vB
```

Current unit:

```text
1 XPQ = 1,000,000 paqus
```

Example:

```text
Virtual size : 1994
Fee rate     : 1 paqus/vB
Fee          : 1994 paqus = 0.001994 XPQ
```

QCash deposits are usually larger than withdraws because deposits carry a proof
and authorization for each cash coin. Post-quantum signatures make those proofs
larger than ordinary account transfer data.

## Wallet CLI Commands

### Create A Wallet

For this directory layout:

```text
MyPaqus/
  Node/
  Wallet/
```

Create a wallet for the node:

```bash
cd MyPaqus/Wallet
cargo run -- new ../Node/wallet.json
```

Run the node:

```bash
cd ../Node
cargo run
```

### Withdraw

```bash
cd MyPaqus/Wallet
cargo run -- cash withdraw 100 --wallet ../Node/wallet.json --out ./cash
```

### Sync Cash Status

```bash
cargo run -- cash sync ./cash
```

### List The Cash Vault

```bash
cargo run -- cash list ./cash
```

### Inspect A Cash File

```bash
cargo run -- cash inspect ./cash/100_C91E1B3A98CDB3A8.XPQ
```

### Deposit

```bash
cargo run -- cash deposit ./cash/100_C91E1B3A98CDB3A8.XPQ \
  --to PX1...
```

## Mempool Note

The node currently allows one pending QCash transaction per signer in the
extension mempool. If a withdraw or deposit is still pending, another QCash
transaction from the same wallet can be rejected until the first one is included
in a block.

Possible message:

```text
transaction already exists in mempool
```

In practice, that means:

```text
this wallet already has a pending QCash transaction
```

Wait for the transaction to enter a block, or mine a block, before creating the
next QCash transaction from the same wallet.

## On-chain And Off-chain Balance

- **On-chain**: account balance in the ledger.
- **Off-chain**: local cash files that the ledger still considers spendable.
- **Pending QCash**: a file exists, but the coin is not mature yet.
- **Spent/unknown**: the file should not be treated as spendable.

Wallet balance shows:

```text
On-chain
Available
Off-chain
Cash pending
Cash spent
Total ready
Total known
```

## Safe Use

- Back up the cash directory regularly.
- Do not deposit files unless their status is `ready`.
- Do not delete a cash file just because the withdraw transaction is confirmed;
  the file is the bearer secret.
- After deposit is confirmed, the old file can be treated as spent, but the
  ledger/RPC remains the source of truth.
- Do not expose node RPC publicly. P2P can be public; RPC should stay local or
  be protected by your own access controls.

