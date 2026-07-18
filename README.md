# Paqus Wallet

Standalone wallet CLI for Paqus. It creates wallet files, derives addresses,
signs transactions, queries node RPC, and submits signed transactions.

Version 0.2.2 targets Paqus core 0.2.5 and the current SHA3-512/ASERT network.

## Quick Start

Open the interactive menu:

```bash
cargo run
```

Create a wallet:

```bash
cargo run -- new wallet.json
```

## Pool payouts

Preview mature mining-pool allocations without signing or submitting them:

```bash
cargo run -- pool-payout \
  --ledger ./pool-accounting.jsonl \
  --wallet ./pool-wallet.json \
  --rpc 127.0.0.1:6666
```

After reviewing the totals, repeat with `--execute`. The executor verifies that
the encrypted wallet owns the pool address, waits for reward maturity, assigns
sequential nonces, and syncs each accepted payment to
`pool-payout-receipts.jsonl`. A resumed run skips payouts already recorded in
the receipt file.

The CLI prompts for a hidden PIN of at least six digits. For automation, inject
it through the `PAQUS_WALLET_PIN` environment variable or a secret manager
rather than a command-line argument. For an interactive shell:

```bash
read -rsp 'Wallet PIN: ' PAQUS_WALLET_PIN
export PAQUS_WALLET_PIN
cargo run -- new wallet.json
unset PAQUS_WALLET_PIN
```

Migrate a legacy plaintext wallet without deleting the original:

```bash
cargo run -- migrate mywallet.json mywallet.encrypted.wallet.json
```

Print the secret key too:

```bash
cargo run -- new wallet.json --show-secret
```

Derive an address from a secret key:

```bash
cargo run -- address <secret-key-hex>
```

Check balance through a running node RPC:

```bash
cargo run -- balance
```

Track global mined supply, target supply, transaction count, fees, and transfer
volume:

```bash
cargo run -- stats
```

Track mined coin, matured mining rewards, collected mining fees, and transaction
totals for one address:

```bash
cargo run -- address-stats
```

View node mining hashrate through RPC:

```bash
cargo run -- hashrate
```

Send a transaction:

```bash
cargo run -- send <address> 10 --fee 0.01
```

`10` is `10.00 XPQ`, and `--fee 0.01` is `0.01 XPQ`. If `--fee` is omitted,
the wallet uses the default fee of `0.01 XPQ`.
Both commands use `wallet.json` by default.

Inspect an eCash bearer file without exposing its opening secret:

```bash
cargo run -- cash inspect 100+ABC123DEF.XPQ
```

Withdraw whole XPQ into bearer files using automatic denominations:

```bash
cargo run -- cash withdraw 1000 --out ./cash --wallet wallet.json
```

The wallet writes crash-recovery files with the `.XPQ.pending` suffix before
submitting the transaction. After the node accepts it, those files are renamed
to `.XPQ`. They become usable after the protocol's 100-block withdraw maturity.
Any fractional part remains in the on-chain account.

Deposit an eCash file. The wallet derives the coin spending key locally and
signs an authorization bound to the recipient address; the opening secret is
never sent to the node:

```bash
cargo run -- cash deposit 100+ABC123DEF.XPQ \
  --to <recipient-address> \
  --wallet wallet.json \
  --fee 0.01
```

Print signed transaction hex without broadcasting:

```bash
cargo run -- send \
  --to <address> \
  --amount 10 \
  --fee 0.01
```

Broadcast the advanced form:

```bash
cargo run -- send \
  --to <address> \
  --amount 10 \
  --fee 0.01 \
  --submit
```

By default the wallet uses node RPC at
`[2404:8000:1044:4d8:1202:b5ff:feb0:7020]:6666`. Set `PAQUS_RPC_ADDR` once if
your node uses another RPC address:

```bash
export PAQUS_RPC_ADDR='[2404:8000:1044:4d8:1202:b5ff:feb0:7020]:6666'
```

You can still override one command with `--rpc <host:port>`.

## Remote RPC

The wallet does not need to run on the same machine as the node. Point it at any
reachable Paqus node RPC endpoint with `PAQUS_RPC_ADDR`:

```bash
PAQUS_RPC_ADDR='<host-or-ip>:6666' cargo run
```

For IPv6 addresses, wrap the address in brackets:

```bash
PAQUS_RPC_ADDR='[2404:8000:1044:4d8:1202:b5ff:feb0:7020]:6666' cargo run
```

The node must listen on an address reachable by the wallet. On a server, bind RPC
to all IPv6 interfaces with:

```bash
full-node node run ./data/paqus --rpc-listen '[::]:6666'
```

Check the server listener:

```bash
ss -ltnp | grep 6666
```

Expected output should show `*:6666` or `[::]:6666`.

Test RPC from the wallet machine:

```bash
curl 'http://[2404:8000:1044:4d8:1202:b5ff:feb0:7020]:6666/health'
```

Keep public RPC access limited when possible.

## Commands

```text
wallet-cli
wallet-cli menu
wallet-cli new [wallet-path] [--show-secret]
wallet-cli migrate <plaintext-wallet> [encrypted-wallet]
wallet-cli address <secret-key-hex>
wallet-cli balance [address] [--wallet path] [--rpc host:port]
wallet-cli stats [--rpc host:port]
wallet-cli address-stats [address] [--wallet path] [--rpc host:port]
wallet-cli hashrate [--rpc host:port]
wallet-cli pay <address> <amount-xpq> [--wallet path] [--fee xpq] [--rpc host:port]
wallet-cli send <address> <amount-xpq> [--wallet path] [--nonce n] [--fee xpq] [--rpc host:port]
wallet-cli send [--wallet path] --to <address> --amount xpq [--nonce n] [--fee xpq] [--submit] [--rpc host:port]
```

Commands use `wallet.json` by default. Pass `--wallet <path>` only when you want
another wallet file.

Addresses are normally displayed as uppercase `PX1...` wallet addresses.
Legacy 20-byte hex addresses are still accepted for older scripts.

New wallet files encrypt `secret_key` with Argon2id and XChaCha20-Poly1305 and
are created with permission `0600` on Unix. They still must not be committed or
shared. Legacy plaintext wallets remain readable so they can be migrated, and
produce a warning whenever they are loaded.

## Interactive Menu

The menu can query these node RPC endpoints without typing `curl`:

```text
/health
/status
/peers
/chain
/balance/<wallet-address>
/blocks/latest
/blocks/<height>
/blocks/hash/<block-hash>
/tx/<tx-hash>
/address/<address>
/accounts
/mempool
```

Inside the menu, type `b` or `back` at prompts to return to the main menu.
RPC queries use the current session RPC address, so you do not need to enter it
for every request. Use `Change RPC for this session` when you want to switch
nodes.
After a menu action prints output, press Enter or type `b`/`back` to show the
main menu again.

RPC responses are shown as readable summaries. Unknown response shapes fall back
to pretty JSON.
