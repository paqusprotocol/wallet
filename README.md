# Paqus Wallet CLI

Standalone wallet CLI for Paqus. It creates wallet files, derives addresses,
signs transactions, queries node RPC, submits transfers, and manages QCash bearer
files.

Wallet files are plaintext JSON and contain `secret_key`. Keep them private,
back them up carefully, and never commit them.

## Quick Start

Repository layout example:

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

Open the interactive wallet menu:

```bash
cd ../Wallet
cargo run
```

## Wallet Commands

Create a wallet:

```bash
cargo run -- new wallet.json
```

Print the secret key too:

```bash
cargo run -- new wallet.json --show-secret
```

Derive an address from a secret key:

```bash
cargo run -- address <secret-key-hex>
```

Check wallet balance:

```bash
cargo run -- balance --wallet ../Node/wallet.json
```

The balance view separates:

```text
On-chain
Available
Incoming
Outgoing
Locked
Off-chain
Cash pending
Cash spent
Total ready
Total known
```

Global chain stats:

```bash
cargo run -- stats
```

Address activity:

```bash
cargo run -- address-stats --wallet ../Node/wallet.json
```

Node hashrate:

```bash
cargo run -- hashrate
```

## Sending XPQ

Send a transfer:

```bash
cargo run -- send <recipient-address> 10 \
  --wallet ../Node/wallet.json
```

If `--fee` is omitted, wallet-cli signs once to measure virtual size and then
uses the default policy fee:

```text
1 paqus/vB
```

Unit:

```text
1 XPQ = 1,000,000 paqus
```

## QCash

QCash converts on-chain XPQ into bearer cash files. Whoever controls an unspent
`.XPQ` file can deposit it back on-chain.

Withdraw whole XPQ into cash files:

```bash
cargo run -- cash withdraw 100 \
  --wallet ../Node/wallet.json \
  --out ./cash
```

Cash file names use:

```text
<denomination>_<short_coin_id>.XPQ
```

Example:

```text
100_C91E1B3A98CDB3A8.XPQ
```

The file is created immediately so the bearer secret is not lost. Ledger status
still decides whether the coin is pending, spendable, or already spent.

Sync status for one file or a directory:

```bash
cargo run -- cash sync ./cash
```

List local cash vault:

```bash
cargo run -- cash list ./cash
```

Inspect a cash file without printing its secret:

```bash
cargo run -- cash inspect ./cash/100_C91E1B3A98CDB3A8.XPQ
```

Deposit a mature cash file:

```bash
cargo run -- cash deposit ./cash/100_C91E1B3A98CDB3A8.XPQ \
  --to <recipient-address> \
  --wallet ../Node/wallet.json
```

Deposit of an immature or already-spent file is rejected by ledger validation.

Backup a cash vault:

```bash
cargo run -- cash backup ./cash ./qcash-backup-20260722
```

Recover into a new or empty directory:

```bash
cargo run -- cash recover ./qcash-backup-20260722 ./cash-restored
```

QCash files are bearer assets. Backups are not encrypted by wallet-cli.

See [`QCASH.md`](QCASH.md) for the complete QCash lifecycle.

## RPC

By default wallet-cli uses:

```text
127.0.0.1:6666
```

Override for one command:

```bash
cargo run -- balance --rpc 127.0.0.1:6666
```

Or set an environment variable:

```bash
export PAQUS_RPC_ADDR=127.0.0.1:6666
cargo run -- balance
```

For IPv6 RPC addresses, use brackets:

```bash
export PAQUS_RPC_ADDR='[2404:8000:1044:4d8:822b:f9ff:fee2:365]:6666'
```

Do not expose node RPC publicly unless you put it behind your own access
controls.

## Build

```bash
cargo check --tests
cargo build --release
```
