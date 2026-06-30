# Paqus Wallet

Standalone wallet CLI for Paqus. It creates wallet files, derives addresses,
signs transactions, queries node RPC, and submits signed transactions.

## Quick Start

Open the interactive menu:

```bash
cargo run
```

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

Check balance through a running node RPC:

```bash
cargo run -- balance
```

Send a transaction:

```bash
cargo run -- send <recipient-address-hex> 10 --fee 1
```

`10` is the amount, and `--fee 1` is the transaction fee. If `--fee` is omitted,
the wallet uses the default fee of `1`.
Both commands use `wallet.json` by default.

Print signed transaction hex without broadcasting:

```bash
cargo run -- send \
  --to <recipient-address-hex> \
  --amount 10 \
  --fee 1
```

Broadcast the advanced form:

```bash
cargo run -- send \
  --to <recipient-address-hex> \
  --amount 10 \
  --fee 1 \
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
paqus-node node run ./data/paqus --rpc-listen '[::]:6666'
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
paqus-wallet
paqus-wallet menu
paqus-wallet new [wallet-path] [--show-secret]
paqus-wallet address <secret-key-hex>
paqus-wallet balance [address-hex] [--wallet path] [--rpc host:port]
paqus-wallet pay <address-hex> <amount> [--wallet path] [--fee units] [--rpc host:port]
paqus-wallet send <address-hex> <amount> [--wallet path] [--nonce n] [--fee units] [--rpc host:port]
paqus-wallet send [--wallet path] --to address-hex --amount units [--nonce n] [--fee units] [--submit] [--rpc host:port]
```

Commands use `wallet.json` by default. Pass `--wallet <path>` only when you want
another wallet file.

Wallet files contain `secret_key`. Do not commit or share them.

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
/address/<address-hex>
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
