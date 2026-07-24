use paqus::{
    block::Nonce,
    consensus::supply::{Amount, DECIMALS, XPQ},
    crypto::{
        Address, PublicKey, SecretKey, address_from_public_key, address_from_string,
        address_to_string, derive_public_key, generate_keypair, sign,
    },
    ledger::{BLOCK_REWARD_MATURITY, QCASH_WITHDRAW_MATURITY},
    qcash::{
        CashCoinFile, WithdrawCashMetadata, cash_coin_commitment, decode_cash_coin_file,
        encode_cash_coin_file,
    },
    state::CashCoinId,
    transaction::{
        QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransaction,
        Transaction,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_RPC_ADDR: &str = "[2404:8000:1044:4d8:e5c4:5b9:93bc:656d]:6666";
const RPC_ADDR_ENV: &str = "PAQUS_RPC_ADDR";
const DEFAULT_WALLET_PATH: &str = "wallet.json";
const WALLET_VERSION: u8 = 1;
const DEFAULT_TRANSACTION_FEE: u64 = XPQ / 1_000_000;
const DEFAULT_TRANSACTION_FEE_XPQ: &str = "auto";
const RPC_HTTP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
struct Wallet {
    address: Address,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl Wallet {
    fn generate() -> Self {
        let keypair = generate_keypair();
        Self::from_keys(keypair.public_key, keypair.secret_key)
    }

    fn from_secret_key(secret_key: SecretKey) -> Self {
        let public_key = derive_public_key(&secret_key);
        Self::from_keys(public_key, secret_key)
    }

    fn from_keys(public_key: PublicKey, secret_key: SecretKey) -> Self {
        Self {
            address: address_from_public_key(&public_key),
            public_key,
            secret_key,
        }
    }

    fn wallet_address(&self) -> String {
        address_to_string(&self.address)
    }

    fn sign_transaction(&self, transaction: Transaction) -> Result<SignedTransaction, String> {
        let signature = sign(&self.secret_key, &transaction.signing_bytes());
        let signed = SignedTransaction::new(transaction, self.public_key, signature);
        signed
            .validate_signed()
            .map_err(|error| format!("signed transaction failed validation: {error}"))?;
        Ok(signed)
    }

    fn sign_qcash_transaction(
        &self,
        transaction: QCashTransaction,
    ) -> Result<SignedQCashTransaction, String> {
        let signature = sign(&self.secret_key, &transaction.signing_bytes());
        let signed = SignedQCashTransaction::new(transaction, self.public_key, signature);
        signed
            .validate_signed()
            .map_err(|error| format!("signed QCash transaction failed validation: {error}"))?;
        Ok(signed)
    }
}

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("menu") | Some("cli") => interactive_menu(),
        Some("-h") | Some("--help") | Some("help") => {
            print_help();
            Ok(())
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("wallet-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("new") => wallet_new(&args[1..]),
        Some("address") => wallet_address(&args[1..]),
        Some("balance") => wallet_balance(&args[1..]),
        Some("stats") | Some("tracking") => wallet_global_stats(&args[1..]),
        Some("address-stats") | Some("address-tracking") => wallet_address_stats(&args[1..]),
        Some("hashrate") => wallet_hashrate(&args[1..]),
        Some("pay") => wallet_pay(&args[1..]),
        Some("send") => wallet_send(&args[1..]),
        Some("pool-payout") => wallet_pool_payout(&args[1..]),
        Some("cash") | Some("qcash") => wallet_cash(&args[1..]),
        Some(command) => Err(format!("unknown wallet command `{command}`. Try --help.")),
    }
}

fn interactive_menu() -> Result<(), String> {
    loop {
        println!();
        println!("Paqus Wallet CLI");
        println!("1. Create wallet");
        println!("2. Show wallet address");
        println!("3. Check wallet balance");
        println!("4. Global chain stats");
        println!("5. Send coin");
        println!("6. QCash");
        println!("7. RPC health");
        println!("8. RPC status");
        println!("9. RPC peers");
        println!("10. RPC chain");
        println!("11. Latest blocks");
        println!("12. Block by height");
        println!("13. Block by hash");
        println!("14. Transaction by hash");
        println!("15. Address explorer");
        println!("16. Accounts");
        println!("17. Mempool");
        println!("18. Hashrate");
        println!("19. Change RPC for this session");
        println!("20. Exit");
        println!("Type b/back to return from prompts.");

        let choice = prompt("Select")?;
        if choice == "20" {
            return Ok(());
        }
        match handle_menu_choice(&choice) {
            Ok(true) => pause_for_menu()?,
            Ok(false) => {}
            Err(error) => {
                println!("error: {error}");
                println!("Returning to menu.");
                pause_for_menu()?;
            }
        }
    }
}

fn handle_menu_choice(choice: &str) -> Result<bool, String> {
    match choice {
        "b" | "back" => {}
        "1" => {
            let Some(path) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            wallet_new(&[path])?;
            return Ok(true);
        }
        "2" => {
            let Some(wallet_path) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            println!("{}", address_to_string(&load_wallet_address(&wallet_path)?));
            return Ok(true);
        }
        "3" => {
            let Some(wallet_path) = prompt_default_back("Wallet file path", DEFAULT_WALLET_PATH)?
            else {
                return Ok(false);
            };
            let rpc_addr = default_rpc_addr();
            let address = load_wallet_address(&wallet_path)?;
            print_wallet_balance_summary(&rpc_addr, &address, "./cash")?;
            return Ok(true);
        }
        "4" => {
            let rpc_addr = default_rpc_addr();
            print_global_stats(&rpc_addr)?;
            return Ok(true);
        }
        "5" => return menu_send_coin(),
        "6" => return menu_qcash(),
        "7" => menu_rpc_get("/health")?,
        "8" => menu_rpc_get("/status")?,
        "9" => menu_rpc_get("/peers")?,
        "10" => menu_rpc_get("/chain")?,
        "11" => menu_rpc_get("/blocks/latest")?,
        "12" => {
            let Some(height) = prompt_back("Height")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/blocks/{height}"))?;
        }
        "13" => {
            let Some(hash) = prompt_back("Block hash")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/blocks/hash/{hash}"))?;
        }
        "14" => {
            let Some(hash) = prompt_back("Transaction hash")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/tx/{hash}"))?;
        }
        "15" => {
            let Some(address) = prompt_default_back("Address", &default_wallet_address_or_empty())?
            else {
                return Ok(false);
            };
            if address.is_empty() {
                println!("No address entered and wallet.json could not be loaded.");
            } else {
                menu_rpc_get(&format!("/address/{address}"))?;
            }
        }
        "16" => menu_rpc_get("/accounts")?,
        "17" => menu_rpc_get("/mempool")?,
        "18" => menu_hashrate()?,
        "19" => {
            let Some(rpc_addr) = prompt_default_back("RPC address", &default_rpc_addr())? else {
                return Ok(false);
            };
            // SAFETY: This CLI is single-threaded while the menu is active.
            unsafe {
                env::set_var(RPC_ADDR_ENV, rpc_addr);
            }
            println!("RPC address set to {}", default_rpc_addr());
        }
        value => {
            println!("Unknown menu `{value}`");
            return Ok(false);
        }
    }
    Ok(true)
}

fn menu_qcash() -> Result<bool, String> {
    println!("QCash");
    println!("1. Withdraw XPQ to cash files");
    println!("2. Deposit cash file");
    println!("3. Inspect cash file");
    println!("4. Sync lifecycle");
    println!("5. List cash vault");
    println!("6. Backup cash vault");
    println!("7. Recover cash vault");
    println!("8. Track file name on explorer");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    match choice.as_str() {
        "1" => {
            let Some(amount) = prompt_back("Amount XPQ")? else {
                return Ok(false);
            };
            let Some(output) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            let Some(wallet) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            wallet_cash_withdraw(&[
                amount,
                "--out".into(),
                output,
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ])?;
        }
        "2" => {
            let Some(file) = prompt_back("Cash file (.XPQ)")? else {
                return Ok(false);
            };
            let Some(recipient) =
                prompt_default_back("Recipient", &default_wallet_address_or_empty())?
            else {
                return Ok(false);
            };
            if recipient.is_empty() {
                return Err("recipient address is required".to_string());
            }
            let Some(wallet) = prompt_default_back("Signing wallet", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            wallet_cash_deposit(&[
                file,
                "--to".into(),
                recipient,
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ])?;
        }
        "3" => {
            let Some(path) = prompt_back("Cash file")? else {
                return Ok(false);
            };
            wallet_cash(&["inspect".into(), path])?;
        }
        "4" => {
            let Some(path) = prompt_default_back("Cash file or directory", "./cash")? else {
                return Ok(false);
            };
            wallet_cash_sync(&[path, "--rpc".into(), default_rpc_addr()])?;
        }
        "5" => {
            let Some(path) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            wallet_cash_list(&[path])?;
        }
        "6" => {
            let Some(source) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            let Some(destination) = prompt_back("New backup directory")? else {
                return Ok(false);
            };
            wallet_cash_backup(&[source, destination])?;
        }
        "7" => {
            let Some(backup) = prompt_back("Backup directory")? else {
                return Ok(false);
            };
            let Some(destination) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            wallet_cash_recover(&[backup, destination])?;
        }
        "8" => {
            let Some(name) = prompt_back("Cash file name or short coin id")? else {
                return Ok(false);
            };
            wallet_cash_track(&[name, "--rpc".into(), default_rpc_addr()])?;
        }
        _ => println!("Unknown QCash selection."),
    }
    Ok(true)
}

fn menu_send_coin() -> Result<bool, String> {
    let Some(to) = prompt_back("Recipient address")? else {
        return Ok(false);
    };
    let Some(amount) = prompt_back("Amount XPQ")? else {
        return Ok(false);
    };
    let Some(fee) = prompt_default_back(
        "Fee XPQ (default auto: 1 paqus/virtual-byte)",
        DEFAULT_TRANSACTION_FEE_XPQ,
    )?
    else {
        return Ok(false);
    };
    let Some(wallet_path) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
        return Ok(false);
    };
    let rpc_addr = default_rpc_addr();
    let mut args = vec![to, amount];
    if fee != "auto" {
        args.push("--fee".to_string());
        args.push(fee);
    }
    args.push("--wallet".to_string());
    args.push(wallet_path);
    args.push("--rpc".to_string());
    args.push(rpc_addr);
    wallet_send_short(&args)?;
    Ok(true)
}

fn menu_rpc_get(path: &str) -> Result<(), String> {
    let rpc_addr = default_rpc_addr();
    print_rpc_get(&rpc_addr, path)
}

fn menu_hashrate() -> Result<(), String> {
    let rpc_addr = default_rpc_addr();
    print_hashrate(&status_value(&rpc_addr)?);
    Ok(())
}

fn print_rpc_get(rpc_addr: &str, path: &str) -> Result<(), String> {
    let body = http_get(rpc_addr, path)?;
    print_rpc_response(path, &body)
}

fn status_value(rpc_addr: &str) -> Result<serde_json::Value, String> {
    let body = http_get(rpc_addr, "/status")?;
    serde_json::from_str(&body)
        .map_err(|error| format!("failed to parse rpc status response: {error}: {body}"))
}

fn print_rpc_response(path: &str, body: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("failed to parse rpc response: {error}: {body}"))?;
    if path == "/health" {
        print_health(&value);
    } else if path == "/status" {
        print_status(&value);
    } else if path == "/chain" {
        print_chain(&value);
    } else if path == "/stats" || path == "/chain/stats" {
        print_chain_stats(&value);
    } else if path == "/peers" {
        print_peers(&value);
    } else if path.starts_with("/balance/") {
        print_balance(&value);
    } else if path == "/blocks/latest" {
        print_latest_blocks(&value);
    } else if path.starts_with("/blocks/") || path.starts_with("/blocks/hash/") {
        print_block(&value);
    } else if path.starts_with("/tx/") {
        print_transaction(&value);
    } else if path.starts_with("/address/") {
        print_address(&value);
    } else if path == "/accounts" {
        print_accounts(&value);
    } else if path == "/mempool" {
        print_mempool(&value);
    } else {
        print_pretty_json(&value);
    }
    Ok(())
}

fn print_health(value: &serde_json::Value) {
    println!("Health");
    print_field("OK", bool_text(value.get("ok")));
}

fn print_status(value: &serde_json::Value) {
    println!("Node Status");
    print_field("Chain", str_value(value.get("chain")));
    print_field("Stage", str_value(value.get("stage")));
    print_field("Protocol", value_text(value.get("protocol_version")));
    print_field("Height", value_text(value.get("height")));
    print_field("Tip", short_value(value.get("tip_hash")));
    print_field(
        "Known",
        value_text(value.get("known_peers").or(value.get("peers"))),
    );
    print_field("Outbound", value_text(value.get("outbound_peers")));
    print_field("Inbound", value_text(value.get("inbound_peers")));
    print_field("Mining", bool_text(value.get("mining")));
    print_field("Hashrate", hashrate_text(value.get("hashrate_hps")));
    print_field("Last attempts", value_text(value.get("last_mine_attempts")));
}

fn print_hashrate(value: &serde_json::Value) {
    println!("Hashrate");
    print_field("Mining", bool_text(value.get("mining")));
    print_field("Hashrate", hashrate_text(value.get("hashrate_hps")));
    print_field("Last attempts", value_text(value.get("last_mine_attempts")));
}

fn print_chain(value: &serde_json::Value) {
    println!("Chain");
    print_field("Name", str_value(value.get("chain")));
    print_field("Coin", str_value(value.get("coin")));
    print_field("Stage", str_value(value.get("stage")));
    print_field("Protocol", value_text(value.get("protocol_version")));
    print_field(
        "Block time",
        format!("{} sec", value_text(value.get("block_time_secs"))),
    );
    print_field("Confirmation", value_text(value.get("confirmation_depth")));
    print_field("Finality", value_text(value.get("finality_depth")));
    print_field("Difficulty", value_text(value.get("difficulty_start")));
}

fn print_chain_stats(value: &serde_json::Value) {
    println!("Global Chain Stats");
    print_field("Chain", str_value(value.get("chain")));
    print_field("Coin", str_value(value.get("coin")));
    print_field("Tip height", value_text(value.get("height")));
    print_field("Block count", value_text(value.get("blocks")));
    print_field(
        "Avg block",
        duration_value_text(value.get("average_block_time_secs")),
    );
    print_field(
        "Target block",
        duration_value_text(value.get("target_block_time_secs")),
    );
    println!();
    print_amount_field("Current supply", value.get("current_supply"));
    print_amount_field("On-chain", value.get("onchain_supply"));
    print_amount_field("Off-chain", value.get("qcash_offchain_supply"));
    print_amount_field("QCash ready", value.get("qcash_spendable_supply"));
    print_amount_field("QCash pending", value.get("qcash_pending_supply"));
    print_amount_field("Total known", value.get("total_known_supply"));
    print_amount_field("Genesis premine", value.get("genesis_premine"));
    print_amount_field("Mined supply", value.get("mined_supply"));
    println!();
    print_amount_field("Miner payouts", value.get("total_coinbase_rewards"));
    print_amount_field("Fees collected", value.get("total_fees_collected"));
    print_field("Tx count", value_text(value.get("total_transactions")));
    print_field("Pending tx", value_text(value.get("pending_transactions")));
    print_amount_field("Transfer vol", value.get("total_transfer_volume"));
    print_amount_field("Tx fees", value.get("total_transaction_fees"));
    print_amount_field("Avg transfer", value.get("average_transfer_amount"));
}

fn print_peers(value: &serde_json::Value) {
    let Some(peers) = value.as_array() else {
        print_pretty_json(value);
        return;
    };
    println!("Peers ({})", peers.len());
    for (index, peer) in peers.iter().enumerate() {
        println!();
        println!("Peer #{}", index + 1);
        print_field("Address", str_value(peer.get("addr")));
        print_field("Failures", value_text(peer.get("failures")));
        print_field("Last tip", value_text(peer.get("last_tip")));
    }
}

fn print_balance(value: &serde_json::Value) {
    println!("Balance");
    print_field("Address", short_value(value.get("address")));
    print_field("Height", value_text(value.get("height")));
    print_field("Exists", bool_text(value.get("exists")));
    print_amount_field("Confirmed", value.get("confirmed"));
    print_amount_field("Available", value.get("available"));
    print_amount_field("Incoming", value.get("pending_incoming"));
    print_amount_field("Outgoing", value.get("pending_outgoing"));
    print_field("Nonce", value_text(value.get("nonce")));
    print_amount_field("Unspendable", value.get("unspendable"));
}

fn print_wallet_balance_summary(
    rpc_addr: &str,
    address: &Address,
    cash_dir: &str,
) -> Result<(), String> {
    let address_text = address_to_string(address);
    let body = http_get(rpc_addr, &format!("/balance/{address_text}"))?;
    let balance: WalletBalanceRpcResponse = serde_json::from_str(&body)
        .map_err(|error| format!("failed to parse balance rpc response: {error}: {body}"))?;
    let offchain = qcash_vault_totals(std::path::Path::new(cash_dir), rpc_addr)?;
    let total_available = balance.available.saturating_add(offchain.spendable);
    let total_known = balance.confirmed.saturating_add(offchain.known);

    println!("Wallet Balance");
    print_field("Address", short_text(&balance.address));
    print_field("Height", balance.height);
    println!();
    print_field("On-chain", format_xpq(balance.confirmed));
    print_field("Available", format_xpq(balance.available));
    print_field("Incoming", format_xpq(balance.pending_incoming));
    print_field("Outgoing", format_xpq(balance.pending_outgoing));
    print_field("Locked", format_xpq(balance.unspendable));
    println!();
    print_field("Off-chain", format_xpq(offchain.spendable));
    print_field("Cash files", offchain.files);
    print_field("Cash pending", format_xpq(offchain.pending));
    print_field("Cash spent", format_xpq(offchain.spent_or_unknown));
    println!();
    print_field("Total ready", format_xpq(total_available));
    print_field("Total known", format_xpq(total_known));
    print_field("Nonce", optional_u64_text(balance.nonce));
    Ok(())
}

fn print_latest_blocks(value: &serde_json::Value) {
    let Some(blocks) = value.as_array() else {
        print_pretty_json(value);
        return;
    };
    println!("Latest Blocks ({})", blocks.len());
    let tip_height = blocks
        .iter()
        .filter_map(|block| block.get("height").and_then(serde_json::Value::as_u64))
        .max();
    for (index, block) in blocks.iter().enumerate() {
        let previous_timestamp = blocks
            .get(index + 1)
            .and_then(|previous_block| previous_block.get("timestamp"))
            .and_then(serde_json::Value::as_u64);
        println!();
        print_block_with_context(block, tip_height, previous_timestamp);
    }
}

fn print_block(value: &serde_json::Value) {
    print_block_with_context(value, None, None);
}

fn print_block_with_context(
    value: &serde_json::Value,
    tip_height: Option<u64>,
    previous_timestamp: Option<u64>,
) {
    println!("Block #{}", value_text(value.get("height")));
    print_field("Hash", short_value(value.get("hash")));
    print_field("Previous", short_value(value.get("previous_hash")));
    print_field("Miner", short_value(value.get("miner_address")));
    print_field("Difficulty", value_text(value.get("difficulty")));
    print_field("Confirmations", confirmations_text(value, tip_height));
    print_field("Age", block_age_text(value));
    print_field("Target", target_block_time_text(value));
    print_field("Block Mined", block_mined_text(value, previous_timestamp));
    print_amount_text_field("Value Moved", value_moved_text(value));
    print_field("Block Nonce", value_text(value.get("nonce")));
    print_field("Tx count", value_text(value.get("tx_count")));
    print_field("Size", format!("{} bytes", value_text(value.get("size"))));
    if let Some(coinbase) = value.get("coinbase").and_then(serde_json::Value::as_object) {
        let subsidy = amount_text(coinbase.get("subsidy"));
        let to = short_value(coinbase.get("to"));
        print_field("Coinbase", format!("{subsidy} to {to}"));
        print_amount_field("Fees", coinbase.get("fees"));
        print_amount_field("Miner payout", coinbase.get("total"));
    }
    print_field("Timestamp", value_text(value.get("timestamp")));
    print_transactions(value.get("transactions"));
}

fn print_transaction(value: &serde_json::Value) {
    println!("Transaction");
    print_tx_fields(value);
}

fn print_address(value: &serde_json::Value) {
    println!("Address");
    print_field("Address", short_value(value.get("address")));
    if let Some(balance) = value.get("balance") {
        println!();
        print_balance(balance);
    }
    print_mined_blocks(value.get("mined_blocks"));
    print_transactions(value.get("transactions"));
}

fn print_mined_blocks(value: Option<&serde_json::Value>) {
    let Some(blocks) = value.and_then(serde_json::Value::as_array) else {
        return;
    };
    println!();
    println!("Mined Blocks ({})", blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        println!();
        println!("Mined #{}", index + 1);
        print_field("Height", value_text(block.get("height")));
        print_field("Hash", short_value(block.get("hash")));
        print_field("Matured", bool_text(block.get("matured")));
        print_field("Matures at", value_text(block.get("maturity_height")));
        print_amount_field("Subsidy", block.get("subsidy"));
        print_amount_field("Fees", block.get("fees"));
        print_amount_field("Total", block.get("total"));
        print_field("Tx count", value_text(block.get("tx_count")));
    }
}

fn print_accounts(value: &serde_json::Value) {
    let Some(accounts) = value.as_array() else {
        print_pretty_json(value);
        return;
    };
    println!("Accounts ({})", accounts.len());
    for (index, account) in accounts.iter().enumerate() {
        println!();
        println!("Account #{}", index + 1);
        print_field("Address", short_value(account.get("address")));
        print_amount_field("Confirmed", account.get("confirmed"));
        print_amount_field("Available", account.get("available"));
        print_amount_field("Unspendable", account.get("unspendable"));
        print_amount_field("Incoming", account.get("pending_incoming"));
        print_amount_field("Outgoing", account.get("pending_outgoing"));
        print_field("Nonce", value_text(account.get("nonce")));
        print_field("Credits", value_text(account.get("credits")));
    }
}

fn print_mempool(value: &serde_json::Value) {
    println!("Mempool");
    print_field("Size", value_text(value.get("size")));
    print_transactions(value.get("transactions"));
}

fn print_transactions(value: Option<&serde_json::Value>) {
    let Some(transactions) = value.and_then(serde_json::Value::as_array) else {
        return;
    };
    println!();
    println!("Transactions ({}, newest first)", transactions.len());
    for tx in transactions {
        println!();
        print_tx_fields(tx);
    }
}

fn print_tx_fields(value: &serde_json::Value) {
    print_field("Family", str_value(value.get("family")));
    print_field("Operation", str_value(value.get("operation")));
    print_field(
        "Txid",
        short_value(value.get("txid").or_else(|| value.get("hash"))),
    );
    print_field("Wtxid", short_value(value.get("wtxid")));
    print_field(
        "Signer",
        short_value(
            value
                .get("signer")
                .or_else(|| value.get("from"))
                .or_else(|| value.get("address")),
        ),
    );
    print_field(
        "Recipient",
        short_value(value.get("recipient").or_else(|| value.get("to"))),
    );
    print_amount_field("Amount", value.get("amount"));
    print_amount_field("Fee", value.get("fee"));
    print_field("Fee rate", tx_fee_rate_text(value));
    print_field("Nonce", value_text(value.get("nonce")));
    print_field("Valid from", value_text(value.get("valid_from")));
    print_field("Valid until", value_text(value.get("valid_until")));
    print_field("Virtual size", value_text(value.get("virtual_size")));
    print_field("Age", tx_age_text(value));
    print_field("Timestamp", value_text(value.get("timestamp")));
    print_field("Height", value_text(value.get("block_height")));
    print_field("Block", short_value(value.get("block_hash")));
    print_field("Status", str_value(value.get("status")));
}

fn print_field(label: &str, value: impl std::fmt::Display) {
    println!("{label:<13} : {value}");
}

fn tx_fee_rate_text(value: &serde_json::Value) -> String {
    let Some(fee) = value.get("fee").and_then(serde_json::Value::as_u64) else {
        return "none".to_string();
    };
    let Some(virtual_size) = value
        .get("virtual_size")
        .and_then(serde_json::Value::as_u64)
    else {
        return "none".to_string();
    };
    if virtual_size == 0 {
        return "infinite".to_string();
    }
    let whole = fee / virtual_size;
    let fractional = fee % virtual_size;
    if fractional == 0 {
        return format!("{whole} paqus/vB");
    }
    let scaled = fractional.saturating_mul(1_000) / virtual_size;
    format!("{whole}.{scaled:03} paqus/vB")
}

fn print_amount_field(label: &str, value: Option<&serde_json::Value>) {
    print_field(label, amount_text(value));
}

fn print_amount_text_field(label: &str, value: impl AsRef<str>) {
    print_field(label, amount_units_text(value.as_ref()));
}

fn print_pretty_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(pretty) => println!("{pretty}"),
        Err(_) => println!("{value}"),
    }
}

fn value_text(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Null) | None => "none".to_string(),
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
    }
}

fn duration_value_text(value: Option<&serde_json::Value>) -> String {
    let Some(seconds) = value.and_then(serde_json::Value::as_u64) else {
        return "none".to_string();
    };
    format_duration(seconds)
}

fn amount_text(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Number(number)) => amount_units_text(&number.to_string()),
        Some(serde_json::Value::String(value)) => amount_units_text(value),
        Some(serde_json::Value::Null) | None => "none".to_string(),
        Some(value) => amount_units_text(&value.to_string()),
    }
}

fn amount_units_text(value: &str) -> String {
    let Ok(units) = value.parse::<u64>() else {
        return value.to_string();
    };
    format_xpq(units)
}

fn format_xpq(units: u64) -> String {
    let whole = units / XPQ;
    let fractional = units % XPQ;
    format!(
        "{}.{fractional:0width$} XPQ",
        format_grouped_u64(whole),
        width = DECIMALS as usize
    )
}

fn format_grouped_u64(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn block_age_text(value: &serde_json::Value) -> String {
    if let Some(age_secs) = value.get("age_secs").and_then(serde_json::Value::as_u64) {
        return format!("{} ago", format_duration(age_secs));
    }

    let Some(timestamp) = value.get("timestamp").and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(timestamp);
    format!("{} ago", format_duration(now.saturating_sub(timestamp)))
}

fn tx_age_text(value: &serde_json::Value) -> String {
    if let Some(age_secs) = value.get("age_secs").and_then(serde_json::Value::as_u64) {
        return format!("{} ago", format_duration(age_secs));
    }

    let Some(timestamp) = value.get("timestamp").and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(timestamp);
    format!("{} ago", format_duration(now.saturating_sub(timestamp)))
}

fn confirmations_text(value: &serde_json::Value, tip_height: Option<u64>) -> String {
    if let Some(confirmations) = value
        .get("confirmations")
        .and_then(serde_json::Value::as_u64)
    {
        return confirmations.to_string();
    }

    let Some(height) = value.get("height").and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    tip_height
        .map(|tip| tip.saturating_sub(height).saturating_add(1).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn target_block_time_text(value: &serde_json::Value) -> String {
    let target = value
        .get("target_block_time_secs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(300);
    format_duration(target)
}

fn block_mined_text(value: &serde_json::Value, previous_timestamp: Option<u64>) -> String {
    let seconds = value
        .get("block_time_secs")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            let timestamp = value.get("timestamp").and_then(serde_json::Value::as_u64)?;
            Some(timestamp.saturating_sub(previous_timestamp?))
        });
    let Some(seconds) = seconds else {
        return "unknown".to_string();
    };
    format_duration(seconds)
}

fn value_moved_text(value: &serde_json::Value) -> String {
    if let Some(value_moved) = value.get("value_moved").and_then(serde_json::Value::as_u64) {
        return value_moved.to_string();
    }

    value
        .get("transactions")
        .and_then(serde_json::Value::as_array)
        .map(|transactions| {
            transactions
                .iter()
                .filter_map(|transaction| {
                    transaction
                        .get("amount")
                        .and_then(serde_json::Value::as_u64)
                })
                .sum::<u64>()
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn hashrate_text(value: Option<&serde_json::Value>) -> String {
    let Some(hashrate) = value.and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    format_hashrate(hashrate)
}

fn format_hashrate(hashrate: u64) -> String {
    let units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
    let mut value = hashrate as f64;
    let mut unit = units[0];
    for next_unit in units.iter().skip(1) {
        if value < 1_000.0 {
            break;
        }
        value /= 1_000.0;
        unit = next_unit;
    }

    if unit == units[0] {
        format!("{hashrate} {unit}")
    } else {
        format!("{value:.2} {unit}")
    }
}

fn format_duration(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} sec"),
        60..=3_599 => {
            let minutes = seconds / 60;
            if minutes == 1 {
                "1 minute".to_string()
            } else {
                format!("{minutes} minutes")
            }
        }
        3_600..=86_399 => {
            let hours = seconds / 3_600;
            if hours == 1 {
                "1 hour".to_string()
            } else {
                format!("{hours} hours")
            }
        }
        _ => {
            let days = seconds / 86_400;
            if days == 1 {
                "1 day".to_string()
            } else {
                format!("{days} days")
            }
        }
    }
}

fn str_value(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| value_text(value))
}

fn short_value(value: Option<&serde_json::Value>) -> String {
    str_value(value)
}

fn bool_text(value: Option<&serde_json::Value>) -> &'static str {
    match value.and_then(serde_json::Value::as_bool) {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn short_text(value: &str) -> String {
    value.to_string()
}

fn wallet_new(args: &[String]) -> Result<(), String> {
    let show_secret = args.iter().any(|arg| arg == "--show-secret");
    let output_path = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
        .unwrap_or(DEFAULT_WALLET_PATH);
    let wallet = Wallet::generate();

    let address_str = wallet.wallet_address().to_string();
    let public_key_hex = hex::encode(wallet.public_key.0);
    let secret_key_hex = hex::encode(wallet.secret_key.0);

    save_wallet(output_path, &wallet)?;
    println!("Wallet successfully saved to `{output_path}`");
    println!("address: {address_str}");
    println!("public_key: {public_key_hex}");
    if show_secret {
        println!("secret_key: {secret_key_hex}");
    } else {
        println!("secret_key: saved in plaintext (rerun with --show-secret to print it)");
    }
    Ok(())
}

fn wallet_address(args: &[String]) -> Result<(), String> {
    let secret_key = parse_secret_key(args.first())?;
    let public_key = derive_public_key(&secret_key);
    let address = address_from_public_key(&public_key);
    println!("{}", address_to_string(&address));
    Ok(())
}

fn wallet_balance(args: &[String]) -> Result<(), String> {
    let mut address = None;
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut cash_dir = "./cash".to_string();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--wallet" => {
                index += 1;
                wallet_path = args
                    .get(index)
                    .ok_or_else(|| "missing value for --wallet".to_string())?
                    .clone();
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            "--cash-dir" | "--cash" => {
                index += 1;
                cash_dir = args
                    .get(index)
                    .ok_or_else(|| "missing value for --cash-dir".to_string())?
                    .clone();
            }
            value if !value.starts_with('-') && address.is_none() => {
                address = Some(parse_address(args.get(index))?);
            }
            value => return Err(format!("unknown wallet balance option `{value}`")),
        }
        index += 1;
    }

    let address = match address {
        Some(address) => address,
        None => load_wallet_address(&wallet_path)?,
    };

    print_wallet_balance_summary(&rpc_addr, &address, &cash_dir)
}

fn wallet_global_stats(args: &[String]) -> Result<(), String> {
    let mut rpc_addr = default_rpc_addr();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            value => return Err(format!("unknown wallet stats option `{value}`")),
        }
        index += 1;
    }

    print_global_stats(&rpc_addr)
}

fn print_global_stats(rpc_addr: &str) -> Result<(), String> {
    let body = http_get(rpc_addr, "/stats")?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| format!("failed to parse stats rpc response: {error}: {body}"))?;
    print_chain_stats(&value);
    Ok(())
}

fn wallet_address_stats(args: &[String]) -> Result<(), String> {
    let mut address = None;
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--wallet" => {
                index += 1;
                wallet_path = args
                    .get(index)
                    .ok_or_else(|| "missing value for --wallet".to_string())?
                    .clone();
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            value if !value.starts_with('-') && address.is_none() => {
                address = Some(parse_address(args.get(index))?);
            }
            value => return Err(format!("unknown wallet address-stats option `{value}`")),
        }
        index += 1;
    }

    let address = match address {
        Some(address) => address,
        None => load_wallet_address(&wallet_path)?,
    };

    print_wallet_stats(&rpc_addr, &address)
}

fn print_wallet_stats(rpc_addr: &str, address: &Address) -> Result<(), String> {
    let address_hex = address_to_string(address);
    let body = http_get(rpc_addr, &format!("/address/{address_hex}"))?;
    let response: AddressRpcResponse = serde_json::from_str(&body)
        .map_err(|error| format!("failed to parse address rpc response: {error}: {body}"))?;
    let stats = WalletStats::from_response(&response);

    println!("Wallet Tracking");
    print_field("Address", short_text(&response.address));
    print_field("Height", response.balance.height);
    print_field(
        "Confirmed",
        amount_units_text(&response.balance.confirmed.to_string()),
    );
    print_field(
        "Available",
        amount_units_text(&response.balance.available.to_string()),
    );
    print_field(
        "Unspendable",
        amount_units_text(&response.balance.unspendable.to_string()),
    );
    print_field(
        "Incoming",
        amount_units_text(&response.balance.pending_incoming.to_string()),
    );
    print_field(
        "Outgoing",
        amount_units_text(&response.balance.pending_outgoing.to_string()),
    );
    print_field("Nonce", optional_u64_text(response.balance.nonce));
    println!();
    print_field("Mined blocks", stats.mined_blocks);
    print_field("Maturity", format!("{BLOCK_REWARD_MATURITY} blocks"));
    print_field(
        "Mined total",
        amount_units_text(&stats.mined_total.to_string()),
    );
    print_field(
        "Matured mined",
        amount_units_text(&stats.matured_mined.to_string()),
    );
    print_field(
        "Immature mined",
        amount_units_text(&stats.immature_mined.to_string()),
    );
    print_field(
        "Mining fees",
        amount_units_text(&stats.mining_fees.to_string()),
    );
    print_field(
        "Next maturity",
        optional_u64_text(stats.next_maturity_height),
    );
    println!();
    print_field("Tx count", stats.total_transactions);
    print_field("Received tx", stats.received_transactions);
    print_field("Sent tx", stats.sent_transactions);
    print_field(
        "Received total",
        amount_units_text(&stats.received_total.to_string()),
    );
    print_field(
        "Sent total",
        amount_units_text(&stats.sent_total.to_string()),
    );
    print_field("Fees sent", amount_units_text(&stats.sent_fees.to_string()));
    print_field("Pending tx", stats.pending_transactions);
    Ok(())
}

fn wallet_hashrate(args: &[String]) -> Result<(), String> {
    let mut rpc_addr = default_rpc_addr();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            value => return Err(format!("unknown wallet hashrate option `{value}`")),
        }
        index += 1;
    }

    print_hashrate(&status_value(&rpc_addr)?);
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AddressRpcResponse {
    address: String,
    balance: AddressBalanceRpcResponse,
    #[serde(default)]
    mined_blocks: Vec<MinedBlockRpcResponse>,
    #[serde(default)]
    transactions: Vec<TransactionRpcResponse>,
}

#[derive(Debug, Deserialize)]
struct AddressBalanceRpcResponse {
    height: u64,
    confirmed: u64,
    available: u64,
    pending_incoming: u64,
    pending_outgoing: u64,
    nonce: Option<u64>,
    #[serde(default)]
    unspendable: u64,
}

#[derive(Debug, Deserialize)]
struct WalletBalanceRpcResponse {
    address: String,
    height: u64,
    confirmed: u64,
    available: u64,
    pending_incoming: u64,
    pending_outgoing: u64,
    nonce: Option<u64>,
    #[serde(default)]
    unspendable: u64,
}

#[derive(Debug, Deserialize)]
struct MinedBlockRpcResponse {
    #[serde(default)]
    maturity_height: u64,
    #[serde(default = "default_block_reward_maturity")]
    matured: bool,
    #[serde(default)]
    fees: u64,
    #[serde(default)]
    total: u64,
}

#[derive(Debug, Deserialize)]
struct TransactionRpcResponse {
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    status: String,
}

#[derive(Debug, Default)]
struct WalletStats {
    mined_blocks: u64,
    mined_total: u64,
    matured_mined: u64,
    immature_mined: u64,
    mining_fees: u64,
    next_maturity_height: Option<u64>,
    total_transactions: u64,
    received_transactions: u64,
    sent_transactions: u64,
    received_total: u64,
    sent_total: u64,
    sent_fees: u64,
    pending_transactions: u64,
}

impl WalletStats {
    fn from_response(response: &AddressRpcResponse) -> Self {
        let mut stats = Self {
            mined_blocks: response.mined_blocks.len() as u64,
            ..Self::default()
        };
        for block in &response.mined_blocks {
            stats.mined_total = stats.mined_total.saturating_add(block.total);
            stats.mining_fees = stats.mining_fees.saturating_add(block.fees);
            if block.matured {
                stats.matured_mined = stats.matured_mined.saturating_add(block.total);
            } else {
                stats.immature_mined = stats.immature_mined.saturating_add(block.total);
                stats.next_maturity_height = match stats.next_maturity_height {
                    Some(height) => Some(height.min(block.maturity_height)),
                    None => Some(block.maturity_height),
                };
            }
        }

        for transaction in &response.transactions {
            stats.total_transactions = stats.total_transactions.saturating_add(1);
            if transaction.status == "pending" {
                stats.pending_transactions = stats.pending_transactions.saturating_add(1);
            }
            if transaction.to == response.address {
                stats.received_transactions = stats.received_transactions.saturating_add(1);
                stats.received_total = stats.received_total.saturating_add(transaction.amount);
            }
            if transaction.from == response.address {
                stats.sent_transactions = stats.sent_transactions.saturating_add(1);
                stats.sent_total = stats.sent_total.saturating_add(transaction.amount);
                stats.sent_fees = stats.sent_fees.saturating_add(transaction.fee);
            }
        }

        stats
    }
}

fn default_block_reward_maturity() -> bool {
    false
}

fn optional_u64_text(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn wallet_pay(args: &[String]) -> Result<(), String> {
    let to = parse_address(args.first())?;
    let amount = parse_amount(args.get(1), "amount")?;
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut fee = Amount(DEFAULT_TRANSACTION_FEE);
    let mut index = 2;

    while index < args.len() {
        match args[index].as_str() {
            "--wallet" => {
                index += 1;
                wallet_path = args
                    .get(index)
                    .ok_or_else(|| "missing value for --wallet".to_string())?
                    .clone();
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            "--fee" => {
                index += 1;
                fee = parse_fee(args.get(index))?;
            }
            value => return Err(format!("unknown wallet pay option `{value}`")),
        }
        index += 1;
    }

    submit_wallet_payment(&wallet_path, to, amount, fee, None, &rpc_addr)
}

fn wallet_send(args: &[String]) -> Result<(), String> {
    let short_form = args.len() >= 2 && !args[0].starts_with('-') && !args[1].starts_with('-');
    if short_form {
        return wallet_send_short(args);
    }

    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut to = None;
    let mut amount = None;
    let mut fee = Amount(DEFAULT_TRANSACTION_FEE);
    let mut nonce = None;
    let mut rpc_addr = default_rpc_addr();
    let mut submit = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--wallet" => {
                index += 1;
                wallet_path = args
                    .get(index)
                    .ok_or_else(|| "missing value for --wallet".to_string())?
                    .clone();
            }
            "--to" => {
                index += 1;
                to = Some(parse_address(args.get(index))?);
            }
            "--amount" => {
                index += 1;
                amount = Some(parse_amount(args.get(index), "--amount")?);
            }
            "--fee" => {
                index += 1;
                fee = parse_fee(args.get(index))?;
            }
            "--nonce" => {
                index += 1;
                nonce = Some(parse_nonce(args.get(index))?);
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            "--submit" => submit = true,
            value => return Err(format!("unknown wallet send option `{value}`")),
        }
        index += 1;
    }

    let to = to.ok_or_else(|| "missing --to address".to_string())?;
    let amount = amount.ok_or_else(|| "missing --amount".to_string())?;
    submit_wallet_transaction(&wallet_path, to, amount, fee, nonce, &rpc_addr, submit)
}

#[derive(Debug, Deserialize)]
struct PoolAccountingRound {
    pool_address: String,
    height: u64,
    block_hash: String,
    maturity_height: u64,
    gross_reward: u64,
    payouts: Vec<PoolWorkerPayout>,
}

#[derive(Debug, Deserialize)]
struct PoolWorkerPayout {
    worker: String,
    address: String,
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PoolPayoutReceipt {
    round_block_hash: String,
    round_height: u64,
    worker: String,
    address: String,
    amount: u64,
    fee: u64,
    nonce: u64,
    tx_hash: String,
    submitted_at_height: u64,
}

fn wallet_pool_payout(args: &[String]) -> Result<(), String> {
    let mut ledger = "pool-accounting.jsonl".to_string();
    let mut receipts = "pool-payout-receipts.jsonl".to_string();
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut fee = Amount(DEFAULT_TRANSACTION_FEE);
    let mut execute = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--ledger" => {
                index += 1;
                ledger = required_option(args, index, "--ledger")?;
            }
            "--receipts" => {
                index += 1;
                receipts = required_option(args, index, "--receipts")?;
            }
            "--wallet" => {
                index += 1;
                wallet_path = required_option(args, index, "--wallet")?;
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = required_option(args, index, "--rpc")?;
            }
            "--fee" => {
                index += 1;
                fee = parse_fee(args.get(index))?;
            }
            "--execute" => execute = true,
            value => return Err(format!("unknown pool-payout option `{value}`")),
        }
        index += 1;
    }

    let height = status_value(&rpc_addr)?
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .ok_or("rpc status is missing height")?;
    let rounds = read_json_lines::<PoolAccountingRound>(&ledger)?;
    let prior_receipts = if std::path::Path::new(&receipts).exists() {
        read_json_lines::<PoolPayoutReceipt>(&receipts)?
    } else {
        Vec::new()
    };
    let paid = prior_receipts
        .iter()
        .map(receipt_key)
        .collect::<HashSet<_>>();
    let wallet_address = address_to_string(&load_wallet_address(&wallet_path)?);
    let mut pending = Vec::new();
    for round in rounds
        .iter()
        .filter(|round| round.maturity_height <= height)
    {
        if round.pool_address != wallet_address {
            return Err(format!(
                "round {} belongs to pool {}, but wallet address is {}",
                round.block_hash, round.pool_address, wallet_address
            ));
        }
        let payout_total = round
            .payouts
            .iter()
            .try_fold(0u64, |total, payout| total.checked_add(payout.amount))
            .ok_or("round payout total overflow")?;
        let fee_count = round
            .payouts
            .iter()
            .filter(|payout| payout.amount > 0)
            .count() as u64;
        let required_fees = fee.0.checked_mul(fee_count).ok_or("payout fee overflow")?;
        let reserve = round.gross_reward.saturating_sub(payout_total);
        if required_fees > reserve {
            return Err(format!(
                "round {} fee reserve is insufficient: need {}, available {} base units",
                round.block_hash, required_fees, reserve
            ));
        }
        for payout in &round.payouts {
            if payout.amount > 0 && !paid.contains(&payout_key(round, payout)) {
                let address = parse_address_string(&payout.address).map_err(|error| {
                    format!(
                        "invalid payout address for worker {}: {error}",
                        payout.worker
                    )
                })?;
                pending.push((round, payout, address));
            }
        }
    }

    if !execute {
        println!(
            "{}",
            serde_json::json!({
                "execute": false,
                "height": height,
                "mature_unpaid_payouts": pending.len(),
                "amount": pending.iter().map(|(_, payout, _)| payout.amount).sum::<u64>(),
                "fees": fee.0.saturating_mul(pending.len() as u64),
                "hint": "review this preview, then repeat with --execute"
            })
        );
        return Ok(());
    }

    let wallet = load_wallet(&wallet_path)?;
    let mut nonce = resolve_wallet_nonce(&wallet.address, &rpc_addr)?;
    for (round, payout, address) in pending {
        let transaction = Transaction::new_at(
            wallet.address,
            address,
            Amount(payout.amount),
            fee,
            nonce,
            unix_timestamp()?,
        );
        let signed = wallet.sign_transaction(transaction)?;
        let tx_hash = hex::encode(signed.hash().0);
        let body = format!("{{\"tx\":\"{}\"}}", signed_transaction_to_hex(&signed)?);
        let response = http_post_json(&rpc_addr, "/tx", &body)?;
        let accepted = serde_json::from_str::<serde_json::Value>(&response)
            .ok()
            .and_then(|value| value.get("accepted").and_then(serde_json::Value::as_bool));
        if accepted != Some(true) {
            return Err(format!(
                "node rejected payout for {}: {response}",
                payout.worker
            ));
        }
        append_payout_receipt(
            &receipts,
            &PoolPayoutReceipt {
                round_block_hash: round.block_hash.clone(),
                round_height: round.height,
                worker: payout.worker.clone(),
                address: payout.address.clone(),
                amount: payout.amount,
                fee: fee.0,
                nonce: nonce.0,
                tx_hash,
                submitted_at_height: height,
            },
        )?;
        nonce = Nonce(nonce.0.checked_add(1).ok_or("wallet nonce overflow")?);
    }
    println!(
        "{{\"accepted\":true,\"height\":{height},\"next_nonce\":{}}}",
        nonce.0
    );
    Ok(())
}

fn read_json_lines<T: for<'de> Deserialize<'de>>(path: &str) -> Result<Vec<T>, String> {
    let file = fs::File::open(path).map_err(|error| format!("failed to open {path}: {error}"))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .filter_map(|(index, line)| match line {
            Ok(line) if line.trim().is_empty() => None,
            result => Some((index, result)),
        })
        .map(|(index, line)| {
            let line = line.map_err(|error| format!("failed to read {path}: {error}"))?;
            serde_json::from_str(&line)
                .map_err(|error| format!("invalid JSON in {path} line {}: {error}", index + 1))
        })
        .collect()
}

fn payout_key(round: &PoolAccountingRound, payout: &PoolWorkerPayout) -> String {
    format!(
        "{}:{}:{}:{}",
        round.block_hash, payout.worker, payout.address, payout.amount
    )
}

fn receipt_key(receipt: &PoolPayoutReceipt) -> String {
    format!(
        "{}:{}:{}:{}",
        receipt.round_block_hash, receipt.worker, receipt.address, receipt.amount
    )
}

fn append_payout_receipt(path: &str, receipt: &PoolPayoutReceipt) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("open receipt file: {error}"))?;
    serde_json::to_writer(&mut file, receipt).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_data().map_err(|error| error.to_string())
}

fn wallet_cash(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("inspect") => {
            let path = args
                .get(1)
                .ok_or_else(|| "usage: cash inspect <coin.XPQ>".to_string())?;
            let file = load_cash_coin_file(path)?;
            println!(
                "{{\"version\":{},\"coin_id\":\"{}\",\"denomination\":{},\"file\":\"{}\"}}",
                file.version,
                hex::encode(file.coin_id),
                file.denomination.xpq(),
                path
            );
            Ok(())
        }
        Some("withdraw") => wallet_cash_withdraw(&args[1..]),
        Some("deposit") => wallet_cash_deposit(&args[1..]),
        Some("sync") => wallet_cash_sync(&args[1..]),
        Some("track") | Some("status") => wallet_cash_track(&args[1..]),
        Some("list") => wallet_cash_list(&args[1..]),
        Some("backup") => wallet_cash_backup(&args[1..]),
        Some("recover") => wallet_cash_recover(&args[1..]),
        Some(command) => Err(format!(
            "unknown cash command `{command}`; use withdraw, inspect, deposit, sync, track, list, backup, or recover"
        )),
        None => Err(
            "usage: cash <withdraw|inspect|deposit|sync|track|list|backup|recover> ...".to_string(),
        ),
    }
}

fn wallet_cash_withdraw(args: &[String]) -> Result<(), String> {
    let requested_amount = parse_amount(args.first(), "cash amount")?;
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut output_dir = "./cash".to_string();
    let mut fee = Amount(DEFAULT_TRANSACTION_FEE);
    let mut fee_explicit = false;
    let mut nonce = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--wallet" => {
                index += 1;
                wallet_path = required_option(args, index, "--wallet")?;
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = required_option(args, index, "--rpc")?;
            }
            "--out" | "--output-dir" => {
                index += 1;
                output_dir = required_option(args, index, "--out")?;
            }
            "--fee" => {
                index += 1;
                fee = parse_fee(args.get(index))?;
                fee_explicit = fee.0 != DEFAULT_TRANSACTION_FEE;
            }
            "--nonce" => {
                index += 1;
                nonce = Some(parse_nonce(args.get(index))?);
            }
            value => return Err(format!("unknown cash withdraw option `{value}`")),
        }
        index += 1;
    }

    let plan = WithdrawCashMetadata::plan_automatic(requested_amount)
        .map_err(|error| format!("cash amount cannot be withdrawn: {error}"))?;
    let mut secrets = Vec::with_capacity(plan.denominations.len());
    let mut commitments = Vec::with_capacity(plan.denominations.len());
    for _ in &plan.denominations {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|error| format!("secure random generation failed: {error}"))?;
        commitments.push(cash_coin_commitment(&secret));
        secrets.push(secret);
    }
    let metadata = WithdrawCashMetadata::from_automatic_plan(&plan, &commitments)
        .map_err(|error| format!("failed to build withdraw outputs: {error}"))?;
    let wallet = load_wallet(&wallet_path)?;
    let nonce = nonce.unwrap_or(resolve_wallet_nonce(&wallet.address, &rpc_addr)?);
    let mut transaction = QCashTransaction::withdraw(
        wallet.address,
        plan.cash_amount,
        fee,
        nonce,
        metadata.clone(),
    )
    .with_timestamp(unix_timestamp()?);
    if !fee_explicit {
        let estimated = qcash_policy_fee(&wallet, transaction.clone())?;
        transaction.fee = estimated;
    }
    let withdraw_hash = transaction.hash();
    let signed = wallet.sign_qcash_transaction(transaction)?;

    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("failed to create cash output directory {output_dir}: {error}"))?;
    let mut cash_files = Vec::with_capacity(metadata.outputs.len());
    for (output, secret) in metadata.outputs.iter().zip(secrets) {
        let cash_file = CashCoinFile::new(withdraw_hash, output, secret)
            .map_err(|error| format!("failed to create cash file: {error}"))?;
        let file_name = CashCoinId(cash_file.coin_id).file_name(output.denomination);
        let final_path = std::path::Path::new(&output_dir).join(file_name);
        write_new_synced_file(
            &final_path,
            &encode_cash_coin_file(&cash_file).map_err(|error| {
                format!(
                    "failed to encode cash file {}: {error}",
                    final_path.display()
                )
            })?,
        )?;
        cash_files.push(final_path);
    }

    let body = format!("{{\"tx\":\"{}\"}}", hex::encode(signed.to_bytes()));
    let response = http_post_json(&rpc_addr, "/qcash/tx", &body)?;
    let accepted = serde_json::from_str::<serde_json::Value>(&response)
        .ok()
        .and_then(|value| value.get("accepted").and_then(serde_json::Value::as_bool))
        == Some(true);
    if !accepted {
        for path in &cash_files {
            let _ = fs::remove_file(path);
        }
        return Err(format!(
            "node rejected cash withdraw; cash files removed: {response}"
        ));
    }
    println!(
        "{{\"accepted\":true,\"lifecycle\":\"ledger-pending\",\"hash\":\"{}\",\"cash_amount\":{},\"remainder\":{},\"coins\":{},\"maturity_blocks\":{},\"output_dir\":\"{}\",\"next\":\"cash sync {}\"}}",
        hex::encode(withdraw_hash.0),
        plan.cash_amount.0,
        plan.remainder.0,
        cash_files.len(),
        QCASH_WITHDRAW_MATURITY,
        output_dir,
        output_dir
    );
    Ok(())
}

fn required_option(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn write_new_synced_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", path.display()))
}

fn wallet_cash_deposit(args: &[String]) -> Result<(), String> {
    let coin_path = args
        .first()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| "usage: cash deposit <coin.XPQ> --to <address>".to_string())?
        .clone();
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut recipient = None;
    let mut fee = Amount(DEFAULT_TRANSACTION_FEE);
    let mut fee_explicit = false;
    let mut nonce = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--to" => {
                index += 1;
                recipient = Some(parse_address(args.get(index))?);
            }
            "--wallet" => {
                index += 1;
                wallet_path = args
                    .get(index)
                    .ok_or_else(|| "missing value for --wallet".to_string())?
                    .clone();
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            "--fee" => {
                index += 1;
                fee = parse_fee(args.get(index))?;
                fee_explicit = fee.0 != DEFAULT_TRANSACTION_FEE;
            }
            "--nonce" => {
                index += 1;
                nonce = Some(parse_nonce(args.get(index))?);
            }
            value => return Err(format!("unknown cash deposit option `{value}`")),
        }
        index += 1;
    }

    let recipient = recipient.ok_or_else(|| "missing --to address".to_string())?;
    let wallet = load_wallet(&wallet_path)?;
    let nonce = nonce.unwrap_or(resolve_wallet_nonce(&wallet.address, &rpc_addr)?);
    let file = load_cash_coin_file(&coin_path)?;
    let timestamp = unix_timestamp()?;
    let mut transaction = QCashTransaction::deposit_from_files_at(
        wallet.address,
        recipient,
        fee,
        nonce,
        timestamp,
        &[file],
    )
    .map_err(|error| format!("failed to authorize cash coin: {error}"))?;
    if !fee_explicit {
        let estimated = qcash_policy_fee(&wallet, transaction.clone())?;
        let file = load_cash_coin_file(&coin_path)?;
        transaction = QCashTransaction::deposit_from_files_at(
            wallet.address,
            recipient,
            estimated,
            nonce,
            timestamp,
            &[file],
        )
        .map_err(|error| format!("failed to authorize cash coin: {error}"))?;
    }
    let signed = wallet.sign_qcash_transaction(transaction)?;
    let body = format!("{{\"tx\":\"{}\"}}", hex::encode(signed.to_bytes()));
    let response = http_post_json(&rpc_addr, "/qcash/tx", &body)?;
    let value: serde_json::Value = serde_json::from_str(&response)
        .map_err(|error| format!("invalid node response: {error}: {response}"))?;
    if value.get("accepted").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(format!(
            "node rejected cash deposit; original file retained: {response}"
        ));
    }
    let deposit_hash = value
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("accepted deposit response has no hash: {response}"))?;
    println!(
        "{{\"accepted\":true,\"lifecycle\":\"ledger-pending\",\"hash\":\"{}\",\"file\":\"{}\",\"next\":\"cash sync {}\"}}",
        deposit_hash, coin_path, coin_path
    );
    Ok(())
}

fn wallet_cash_sync(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or_else(|| "usage: cash sync <coin-file-or-directory> [--rpc host:port]".to_string())?;
    let mut rpc_addr = default_rpc_addr();
    if let Some(index) = args
        .iter()
        .position(|value| value == "--rpc" || value == "--rpc-addr")
    {
        rpc_addr = required_option(args, index + 1, "--rpc")?;
    }
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to inspect cash lifecycle path {path}: {error}"))?;
    let mut files = Vec::new();
    if metadata.is_dir() {
        for entry in
            fs::read_dir(path).map_err(|error| format!("failed to read {path}: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("failed to read directory entry: {error}"))?;
            let value = entry.path().to_string_lossy().into_owned();
            if value.ends_with(".XPQ") {
                files.push(value);
            }
        }
    } else {
        files.push(path.clone());
    }
    let tip = status_value(&rpc_addr)?
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "node status has no height".to_string())?;
    for file_path in files {
        sync_cash_file(&file_path, &rpc_addr, tip)?;
    }
    Ok(())
}

fn sync_cash_file(path: &str, rpc_addr: &str, tip: u64) -> Result<(), String> {
    let file = load_cash_coin_file(path)?;
    let coin_id = hex::encode(file.coin_id);
    let response = http_get(rpc_addr, &format!("/qcash/coin/{coin_id}"))?;
    let coin: serde_json::Value = serde_json::from_str(&response)
        .map_err(|error| format!("failed to parse QCash coin status: {error}: {response}"))?;
    let status = coin
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let lifecycle = match status {
        "pending" => "ledger-pending",
        "spendable" => "ready",
        "spent_or_unknown" => "spent-or-unissued",
        _ => "unknown",
    };
    println!(
        "{{\"file\":\"{path}\",\"coin_id\":\"{coin_id}\",\"lifecycle\":\"{lifecycle}\",\"ledger_status\":\"{status}\",\"tip\":{tip},\"denomination\":{}}}",
        file.denomination.xpq()
    );
    Ok(())
}

fn wallet_cash_track(args: &[String]) -> Result<(), String> {
    let lookup = args
        .first()
        .ok_or_else(|| "usage: cash track <file-name-or-short-id> [--rpc host:port]".to_string())?;
    let mut rpc_addr = default_rpc_addr();
    if let Some(index) = args
        .iter()
        .position(|value| value == "--rpc" || value == "--rpc-addr")
    {
        rpc_addr = required_option(args, index + 1, "--rpc")?;
    }
    let name = qcash_lookup_name(lookup)?;
    println!("{}", http_get(&rpc_addr, &format!("/qcash/file/{name}"))?);
    Ok(())
}

fn qcash_lookup_name(value: &str) -> Result<String, String> {
    let name = std::path::Path::new(value)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(value)
        .trim();
    if name.is_empty() {
        return Err("cash file name or short coin id is required".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err("cash file lookup contains unsupported characters".to_string());
    }
    Ok(name.to_string())
}

fn cash_lifecycle(path: &std::path::Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".XPQ") {
        Some("ready")
    } else {
        None
    }
}

fn cash_files_in(directory: &std::path::Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("failed to read {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("failed to read directory entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "refusing symbolic link in QCash directory: {}",
                entry.path().display()
            ));
        }
        if file_type.is_file() && cash_lifecycle(&entry.path()).is_some() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

#[derive(Default)]
struct QCashVaultTotals {
    files: usize,
    known: u64,
    spendable: u64,
    pending: u64,
    spent_or_unknown: u64,
}

fn qcash_vault_totals(
    directory: &std::path::Path,
    rpc_addr: &str,
) -> Result<QCashVaultTotals, String> {
    if !directory.exists() {
        return Ok(QCashVaultTotals::default());
    }
    let files = cash_files_in(directory)?;
    let mut totals = QCashVaultTotals::default();
    for path in files {
        let file = load_cash_coin_file(
            path.to_str()
                .ok_or_else(|| "cash path is not valid UTF-8".to_string())?,
        )?;
        totals.files += 1;
        let amount = file.denomination.amount().0;
        let coin_id = hex::encode(file.coin_id);
        let response = http_get(rpc_addr, &format!("/qcash/coin/{coin_id}"))?;
        let status = serde_json::from_str::<serde_json::Value>(&response)
            .ok()
            .and_then(|value| {
                value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "spent_or_unknown".to_string());
        match status.as_str() {
            "spendable" => {
                totals.spendable = totals.spendable.saturating_add(amount);
                totals.known = totals.known.saturating_add(amount);
            }
            "pending" => {
                totals.pending = totals.pending.saturating_add(amount);
                totals.known = totals.known.saturating_add(amount);
            }
            _ => {
                totals.spent_or_unknown = totals.spent_or_unknown.saturating_add(amount);
            }
        }
    }
    Ok(totals)
}

fn wallet_cash_list(args: &[String]) -> Result<(), String> {
    let directory = std::path::Path::new(args.first().map(String::as_str).unwrap_or("./cash"));
    let files = cash_files_in(directory)?;
    let mut totals = std::collections::BTreeMap::<&str, (usize, u64)>::new();
    for path in &files {
        let file = load_cash_coin_file(
            path.to_str()
                .ok_or_else(|| "cash path is not valid UTF-8".to_string())?,
        )?;
        let lifecycle = cash_lifecycle(path).expect("filtered cash file must have lifecycle");
        let total = totals.entry(lifecycle).or_default();
        total.0 += 1;
        total.1 = total.1.saturating_add(file.denomination.amount().0);
        println!(
            "{{\"file\":\"{}\",\"lifecycle\":\"{}\",\"coin_id\":\"{}\",\"denomination\":{}}}",
            path.display(),
            lifecycle,
            hex::encode(file.coin_id),
            file.denomination.xpq()
        );
    }
    let coins: usize = totals.values().map(|(count, _)| *count).sum();
    let value: u64 = totals.values().map(|(_, amount)| *amount).sum();
    println!(
        "{{\"directory\":\"{}\",\"coins\":{},\"value\":{},\"states\":{}}}",
        directory.display(),
        coins,
        value,
        serde_json::to_string(&totals).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn create_private_directory(path: &std::path::Path) -> Result<(), String> {
    fs::create_dir(path).map_err(|error| {
        format!(
            "failed to create private directory {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("failed to secure {}: {error}", path.display()))?;
    }
    Ok(())
}

fn copy_cash_file_exclusive(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), String> {
    let bytes = fs::read(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
    write_new_synced_file(destination, &bytes)
}

fn wallet_cash_backup(args: &[String]) -> Result<(), String> {
    let source = args
        .first()
        .ok_or_else(|| "usage: cash backup <cash-directory> <new-backup-directory>".to_string())?;
    let destination = args
        .get(1)
        .ok_or_else(|| "usage: cash backup <cash-directory> <new-backup-directory>".to_string())?;
    let source = std::path::Path::new(source);
    let destination = std::path::Path::new(destination);
    let files = cash_files_in(source)?;
    if files.is_empty() {
        return Err("cash directory contains no QCash files".to_string());
    }
    for path in &files {
        load_cash_coin_file(
            path.to_str()
                .ok_or_else(|| "cash path is not valid UTF-8".to_string())?,
        )?;
    }
    create_private_directory(destination)?;
    let mut copied = 0_usize;
    for path in files {
        let name = path
            .file_name()
            .ok_or_else(|| "cash file has no name".to_string())?;
        copy_cash_file_exclusive(&path, &destination.join(name))?;
        copied += 1;
    }
    println!(
        "{{\"backup\":true,\"source\":\"{}\",\"destination\":\"{}\",\"coins\":{},\"warning\":\"unencrypted bearer backup\"}}",
        source.display(),
        destination.display(),
        copied
    );
    Ok(())
}

fn wallet_cash_recover(args: &[String]) -> Result<(), String> {
    let backup = args
        .first()
        .ok_or_else(|| "usage: cash recover <backup-directory> <cash-directory>".to_string())?;
    let destination = args
        .get(1)
        .ok_or_else(|| "usage: cash recover <backup-directory> <cash-directory>".to_string())?;
    let backup = std::path::Path::new(backup);
    let destination = std::path::Path::new(destination);
    let files = cash_files_in(backup)?;
    if files.is_empty() {
        return Err("backup contains no QCash files".to_string());
    }
    for path in &files {
        load_cash_coin_file(
            path.to_str()
                .ok_or_else(|| "cash path is not valid UTF-8".to_string())?,
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| "cash file has no name".to_string())?;
        if destination.join(name).exists() {
            return Err(format!(
                "recovery would overwrite existing file {}",
                destination.join(name).display()
            ));
        }
    }
    if !destination.exists() {
        create_private_directory(destination)?;
    } else if !destination.is_dir() {
        return Err("cash recovery destination is not a directory".to_string());
    }
    let mut restored = 0_usize;
    for path in files {
        load_cash_coin_file(
            path.to_str()
                .ok_or_else(|| "cash path is not valid UTF-8".to_string())?,
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| "cash file has no name".to_string())?;
        copy_cash_file_exclusive(&path, &destination.join(name))?;
        restored += 1;
    }
    println!(
        "{{\"recovered\":true,\"backup\":\"{}\",\"destination\":\"{}\",\"coins\":{}}}",
        backup.display(),
        destination.display(),
        restored
    );
    Ok(())
}

fn load_cash_coin_file(path: &str) -> Result<CashCoinFile, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read cash file {path}: {error}"))?;
    decode_cash_coin_file(&bytes).map_err(|error| format!("invalid cash file {path}: {error}"))
}

fn wallet_send_short(args: &[String]) -> Result<(), String> {
    let to = parse_address(args.first())?;
    let amount = parse_amount(args.get(1), "amount")?;
    let mut wallet_path = DEFAULT_WALLET_PATH.to_string();
    let mut rpc_addr = default_rpc_addr();
    let mut fee = Amount(DEFAULT_TRANSACTION_FEE);
    let mut nonce = None;
    let mut index = 2;

    while index < args.len() {
        match args[index].as_str() {
            "--wallet" => {
                index += 1;
                wallet_path = args
                    .get(index)
                    .ok_or_else(|| "missing value for --wallet".to_string())?
                    .clone();
            }
            "--rpc" | "--rpc-addr" => {
                index += 1;
                rpc_addr = args
                    .get(index)
                    .ok_or_else(|| "missing value for --rpc".to_string())?
                    .clone();
            }
            "--fee" => {
                index += 1;
                fee = parse_fee(args.get(index))?;
            }
            "--nonce" => {
                index += 1;
                nonce = Some(parse_nonce(args.get(index))?);
            }
            value => return Err(format!("unknown wallet send option `{value}`")),
        }
        index += 1;
    }

    submit_wallet_payment(&wallet_path, to, amount, fee, nonce, &rpc_addr)
}

fn submit_wallet_payment(
    wallet_path: &str,
    to: Address,
    amount: Amount,
    fee: Amount,
    nonce: Option<Nonce>,
    rpc_addr: &str,
) -> Result<(), String> {
    submit_wallet_transaction(wallet_path, to, amount, fee, nonce, rpc_addr, true)
}

fn submit_wallet_transaction(
    wallet_path: &str,
    to: Address,
    amount: Amount,
    fee: Amount,
    nonce: Option<Nonce>,
    rpc_addr: &str,
    submit: bool,
) -> Result<(), String> {
    let wallet = load_wallet(wallet_path)?;
    let nonce = nonce.unwrap_or(resolve_wallet_nonce(&wallet.address, rpc_addr)?);
    let timestamp = unix_timestamp()?;
    let transaction = Transaction::new_at(wallet.address, to, amount, fee, nonce, timestamp);
    let mut signed = wallet
        .sign_transaction(transaction)
        .map_err(|error| format!("failed to sign transaction: {error}"))?;
    // The default CLI fee is a sentinel. Unless --fee overrides it, sign once
    // to measure vsize, then use exactly 1 paqus per virtual byte.
    if fee.0 == DEFAULT_TRANSACTION_FEE {
        let fee = policy_fee_for_virtual_size(signed.virtual_size());
        signed = wallet
            .sign_transaction(Transaction::new_at(
                wallet.address,
                to,
                amount,
                fee,
                nonce,
                timestamp,
            ))
            .map_err(|error| format!("failed to sign transaction: {error}"))?;
    }
    let tx_hex = signed_transaction_to_hex(&signed)?;

    if submit {
        let body = format!("{{\"tx\":\"{tx_hex}\"}}");
        let response = http_post_json(rpc_addr, "/tx", &body)?;
        println!("{response}");
    } else {
        println!(
            "{{\"tx\":\"{}\",\"hash\":\"{}\",\"from\":\"{}\",\"to\":\"{}\",\"amount\":{},\"fee\":{},\"nonce\":{},\"timestamp\":{}}}",
            tx_hex,
            hex::encode(signed.hash().0),
            address_to_string(&signed.transaction.from),
            address_to_string(&signed.transaction.to),
            signed.transaction.amount.0,
            signed.transaction.fee.0,
            signed.transaction.nonce.0,
            signed.transaction.timestamp
        );
    }

    Ok(())
}

fn resolve_wallet_nonce(address: &Address, rpc_addr: &str) -> Result<Nonce, String> {
    let address_hex = address_to_string(address);
    let balance_body = http_get(rpc_addr, &format!("/balance/{address_hex}"))?;
    let balance: BalanceRpcResponse = serde_json::from_str(&balance_body)
        .map_err(|error| format!("failed to parse balance rpc response: {error}"))?;
    let mut next_nonce = balance.nonce.unwrap_or(0);

    let mempool_body = http_get(rpc_addr, "/mempool")?;
    let mempool: MempoolRpcResponse = serde_json::from_str(&mempool_body)
        .map_err(|error| format!("failed to parse mempool rpc response: {error}"))?;
    let mut pending_nonces = mempool
        .transactions
        .into_iter()
        .filter_map(|transaction| {
            transaction
                .signer()
                .is_some_and(|signer| signer == address_hex)
                .then_some(transaction.nonce)
        })
        .collect::<Vec<_>>();
    let qcash_body = http_get(rpc_addr, "/qcash/mempool")?;
    let qcash_mempool: QCashMempoolRpcResponse = serde_json::from_str(&qcash_body)
        .map_err(|error| format!("failed to parse QCash mempool rpc response: {error}"))?;
    pending_nonces.extend(
        qcash_mempool
            .transactions
            .into_iter()
            .filter_map(|transaction| {
                (transaction.signer == address_hex).then_some(transaction.nonce)
            }),
    );
    pending_nonces.sort_unstable();
    pending_nonces.dedup();

    for nonce in pending_nonces {
        if nonce == next_nonce {
            next_nonce = next_nonce.saturating_add(1);
        } else if nonce > next_nonce {
            break;
        }
    }

    Ok(Nonce(next_nonce))
}

#[derive(Debug, Deserialize)]
struct BalanceRpcResponse {
    nonce: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MempoolRpcResponse {
    transactions: Vec<MempoolTxRpcResponse>,
}

#[derive(Debug, Deserialize)]
struct MempoolTxRpcResponse {
    signer: Option<String>,
    from: Option<String>,
    nonce: u64,
}

impl MempoolTxRpcResponse {
    fn signer(&self) -> Option<&str> {
        self.signer.as_deref().or(self.from.as_deref())
    }
}

#[derive(Debug, Deserialize)]
struct QCashMempoolRpcResponse {
    transactions: Vec<QCashMempoolTxRpcResponse>,
}

#[derive(Debug, Deserialize)]
struct QCashMempoolTxRpcResponse {
    signer: String,
    nonce: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct WalletFile {
    version: u8,
    address: String,
    public_key: String,
    secret_key: String,
}

fn load_wallet(path: &str) -> Result<Wallet, String> {
    let contents =
        fs::read(path).map_err(|error| format!("failed to read wallet file {path}: {error}"))?;
    load_wallet_bytes(path, &contents)
}

fn load_wallet_address(path: &str) -> Result<Address, String> {
    let contents =
        fs::read(path).map_err(|error| format!("failed to read wallet file {path}: {error}"))?;
    let wallet: WalletFile = serde_json::from_slice(&contents)
        .map_err(|error| format!("failed to parse wallet file {path}: {error}"))?;
    if wallet.version != WALLET_VERSION {
        return Err("unsupported wallet format".to_string());
    }
    parse_address_string(&wallet.address)
}

fn load_wallet_bytes(path: &str, contents: &[u8]) -> Result<Wallet, String> {
    let wallet_file: WalletFile = serde_json::from_slice(contents)
        .map_err(|error| format!("failed to parse wallet file {path}: {error}"))?;
    if wallet_file.version != WALLET_VERSION {
        return Err("unsupported wallet format".to_string());
    }
    let address = parse_address_string(&wallet_file.address)?;
    let secret_key = parse_secret_key(Some(&wallet_file.secret_key))?;
    let wallet = Wallet::from_secret_key(secret_key);
    if wallet.address != address {
        return Err("wallet address does not match secret key".to_string());
    }
    if hex::encode(wallet.public_key.0) != wallet_file.public_key {
        return Err("wallet public key does not match secret key".to_string());
    }
    Ok(wallet)
}

fn save_wallet(path: &str, wallet: &Wallet) -> Result<(), String> {
    let wallet_file = WalletFile {
        version: WALLET_VERSION,
        address: wallet.wallet_address(),
        public_key: hex::encode(wallet.public_key.0),
        secret_key: hex::encode(wallet.secret_key.0),
    };
    let bytes = serde_json::to_vec_pretty(&wallet_file)
        .map_err(|error| format!("failed to serialize wallet: {error}"))?;
    write_new_synced_file(std::path::Path::new(path), &bytes)
}

fn signed_transaction_to_hex(transaction: &SignedTransaction) -> Result<String, String> {
    Ok(hex::encode(transaction.to_bytes()))
}

fn qcash_policy_fee(wallet: &Wallet, transaction: QCashTransaction) -> Result<Amount, String> {
    let signed = wallet.sign_qcash_transaction(transaction)?;
    Ok(policy_fee_for_virtual_size(
        SignedProtocolTransaction::QCash(signed).virtual_size(),
    ))
}

fn policy_fee_for_virtual_size(virtual_size: usize) -> Amount {
    Amount(virtual_size as u64)
}

fn parse_secret_key(value: Option<&String>) -> Result<SecretKey, String> {
    let Some(value) = value else {
        return Err("missing secret key hex".to_string());
    };
    let bytes = hex::decode(value).map_err(|_| "invalid secret key hex".to_string())?;
    let bytes = bytes
        .try_into()
        .map_err(|_| "secret key has invalid length".to_string())?;
    Ok(SecretKey(bytes))
}

fn parse_address(value: Option<&String>) -> Result<Address, String> {
    let Some(value) = value else {
        return Err("missing address".to_string());
    };
    parse_address_string(value)
}

fn parse_address_string(value: &str) -> Result<Address, String> {
    address_from_string(value).or_else(|_| parse_address_hex(value))
}

fn parse_address_hex(value: &str) -> Result<Address, String> {
    let bytes = hex::decode(value).map_err(|_| "invalid address hex".to_string())?;
    let bytes = bytes
        .try_into()
        .map_err(|_| "address has invalid length".to_string())?;
    Ok(Address(bytes))
}

fn parse_amount(value: Option<&String>, flag: &str) -> Result<Amount, String> {
    let value = value.ok_or_else(|| format!("missing value for {flag}"))?;
    parse_xpq_amount(value).map_err(|error| format!("invalid XPQ amount for {flag}: {error}"))
}

fn parse_fee(value: Option<&String>) -> Result<Amount, String> {
    let value = value.ok_or_else(|| "missing value for --fee".to_string())?;
    if value.eq_ignore_ascii_case("auto") {
        return Ok(Amount(DEFAULT_TRANSACTION_FEE));
    }
    parse_xpq_amount(value).map_err(|error| format!("invalid XPQ amount for --fee: {error}"))
}

fn parse_xpq_amount(value: &str) -> Result<Amount, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("amount is empty".to_string());
    }
    if value.starts_with('-') {
        return Err("amount cannot be negative".to_string());
    }

    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next();
    if parts.next().is_some() {
        return Err("amount has more than one decimal point".to_string());
    }
    if whole.is_empty() && fractional.is_none_or(str::is_empty) {
        return Err("amount is empty".to_string());
    }
    if !whole.chars().all(|character| character.is_ascii_digit()) {
        return Err("whole XPQ part must contain digits only".to_string());
    }

    let whole_units = if whole.is_empty() {
        0u64
    } else {
        whole
            .parse::<u64>()
            .map_err(|error| format!("whole XPQ part is too large: {error}"))?
    };

    let fractional_units = match fractional {
        Some("") | None => 0u64,
        Some(value) => {
            if value.len() > 8 {
                return Err("XPQ supports at most 8 decimal places".to_string());
            }
            if !value.chars().all(|character| character.is_ascii_digit()) {
                return Err("fractional XPQ part must contain digits only".to_string());
            }
            let mut padded = value.to_string();
            while padded.len() < 8 {
                padded.push('0');
            }
            padded
                .parse::<u64>()
                .map_err(|error| format!("fractional XPQ part is invalid: {error}"))?
        }
    };

    let units = whole_units
        .checked_mul(XPQ)
        .and_then(|units| units.checked_add(fractional_units))
        .ok_or_else(|| "amount is too large".to_string())?;
    Ok(Amount(units))
}

fn parse_nonce(value: Option<&String>) -> Result<Nonce, String> {
    let value = value.ok_or_else(|| "missing value for --nonce".to_string())?;
    value
        .parse::<u64>()
        .map(Nonce)
        .map_err(|error| format!("invalid nonce: {error}"))
}

fn unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before unix epoch".to_string())
}

fn http_post_json(addr: &str, path: &str, body: &str) -> Result<String, String> {
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid rpc address: {error}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|error| format!("failed to connect rpc: {error}"))?;
    configure_stream(&stream)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to write rpc request: {error}"))?;
    read_http_response(stream)
}

fn http_get(addr: &str, path: &str) -> Result<String, String> {
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid rpc address: {error}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|error| format!("failed to connect rpc: {error}"))?;
    configure_stream(&stream)?;
    let request = format!("GET {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to write rpc request: {error}"))?;
    read_http_response(stream)
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(RPC_HTTP_TIMEOUT))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(RPC_HTTP_TIMEOUT))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;
    Ok(())
}

fn read_http_response(mut stream: TcpStream) -> Result<String, String> {
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                response.extend_from_slice(&buffer[..bytes_read]);
                if response_body_complete(&response)? {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if response_body_complete(&response)? {
                    break;
                }
                return Err(
                    "failed to read rpc response: timed out waiting for node response".to_string(),
                );
            }
            Err(error) => return Err(format!("failed to read rpc response: {error}")),
        }
    }
    let response = String::from_utf8(response)
        .map_err(|error| format!("failed to decode rpc response: {error}"))?;
    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or(response))
}

fn response_body_complete(response: &[u8]) -> Result<bool, String> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(false);
    };
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("failed to decode rpc response headers: {error}"))?;
    let Some(content_length) = headers.lines().find_map(content_length) else {
        return Ok(false);
    };
    Ok(response.len() >= header_end + 4 + content_length)
}

fn content_length(line: &str) -> Option<usize> {
    let (name, value) = line.split_once(':')?;
    name.eq_ignore_ascii_case("content-length")
        .then(|| value.trim().parse().ok())
        .flatten()
}

fn default_rpc_addr() -> String {
    env::var(RPC_ADDR_ENV).unwrap_or_else(|_| DEFAULT_RPC_ADDR.to_string())
}

fn default_wallet_address_or_empty() -> String {
    load_wallet_address(DEFAULT_WALLET_PATH)
        .map(|address| address_to_string(&address))
        .unwrap_or_default()
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|error| format!("failed to read input: {error}"))?;
    Ok(line.trim().to_string())
}

fn prompt_back(label: &str) -> Result<Option<String>, String> {
    let value = prompt(&format!("{label} (b/back to menu)"))?;
    if is_back(&value) {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn prompt_default(label: &str, default: &str) -> Result<String, String> {
    print!("{label} [{default}]: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|error| format!("failed to read input: {error}"))?;
    let value = line.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}

fn prompt_default_back(label: &str, default: &str) -> Result<Option<String>, String> {
    let value = prompt_default(&format!("{label} (b/back to menu)"), default)?;
    if is_back(&value) {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn pause_for_menu() -> Result<(), String> {
    let _ = prompt("Press Enter or type b/back to return to menu")?;
    Ok(())
}

fn is_back(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "b" | "back")
}

fn print_help() {
    println!(
        "\
wallet-cli

Usage:
  wallet-cli
  wallet-cli menu
  wallet-cli new [wallet-path] [--show-secret]
  wallet-cli address <secret-key-hex>
  wallet-cli balance [address] [--wallet path] [--rpc host:port]
  wallet-cli stats [--rpc host:port]
  wallet-cli address-stats [address] [--wallet path] [--rpc host:port]
  wallet-cli hashrate [--rpc host:port]
  wallet-cli pay <address> <amount-xpq> [--wallet path] [--fee xpq] [--rpc host:port]
  wallet-cli send <address> <amount-xpq> [--wallet path] [--nonce n] [--fee xpq] [--rpc host:port]
  wallet-cli send [--wallet path] --to <address> --amount xpq [--nonce n] [--fee xpq] [--submit] [--rpc host:port]
  wallet-cli pool-payout [--ledger file] [--receipts file] [--wallet path] [--fee xpq] [--rpc host:port] [--execute]
  wallet-cli cash withdraw <amount-xpq> [--out directory] [--wallet path] [--nonce n] [--fee xpq] [--rpc host:port]
  wallet-cli cash inspect <coin.XPQ>
  wallet-cli cash deposit <coin.XPQ> --to <address> [--wallet path] [--nonce n] [--fee xpq] [--rpc host:port]
  wallet-cli cash sync <coin-file-or-directory> [--rpc host:port]
  wallet-cli cash track <file-name-or-short-id> [--rpc host:port]
  wallet-cli cash list [cash-directory]
  wallet-cli cash backup <cash-directory> <new-backup-directory>
  wallet-cli cash recover <backup-directory> <cash-directory>

Defaults:
  Wallet path: wallet.json
  RPC address: $PAQUS_RPC_ADDR or [2404:8000:1044:4d8:e5c4:5b9:93bc:656d]:6666
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_xpq_with_protocol_decimals() {
        assert_eq!(format_xpq(XPQ / 100), "0.010000 XPQ");
        assert_eq!(format_xpq(50 * XPQ + XPQ / 100), "50.010000 XPQ");
    }

    #[test]
    fn classifies_qcash_file_lifecycle_suffixes() {
        use std::path::Path;
        assert_eq!(cash_lifecycle(Path::new("coin.XPQ")), Some("ready"));
        assert_eq!(cash_lifecycle(Path::new("coin.XPQ.pending")), None);
        assert_eq!(cash_lifecycle(Path::new("coin.XPQ.deposit-pending")), None);
        assert_eq!(cash_lifecycle(Path::new("coin.XPQ.spent")), None);
        assert_eq!(cash_lifecycle(Path::new("wallet.json")), None);
    }

    #[test]
    fn qcash_backup_and_recovery_are_non_overwriting() {
        use paqus::crypto::TransactionHash;
        use paqus::qcash::CashDenomination;

        let root = std::env::temp_dir().join(format!(
            "wallet-cli-qcash-vault-{}-{}",
            std::process::id(),
            unix_timestamp().unwrap()
        ));
        let source = root.join("source");
        let backup = root.join("backup");
        let recovered = root.join("recovered");
        fs::create_dir_all(&source).unwrap();

        let secret = [42; 32];
        let metadata = WithdrawCashMetadata::with_denominations(
            Amount(XPQ),
            &[CashDenomination::One],
            &[cash_coin_commitment(&secret)],
        )
        .unwrap();
        let cash =
            CashCoinFile::new(TransactionHash([7; 32]), &metadata.outputs[0], secret).unwrap();
        let source_file = source.join("1_TESTCOIN1.XPQ");
        write_new_synced_file(&source_file, &encode_cash_coin_file(&cash).unwrap()).unwrap();

        wallet_cash_backup(&[
            source.to_string_lossy().into_owned(),
            backup.to_string_lossy().into_owned(),
        ])
        .unwrap();
        wallet_cash_recover(&[
            backup.to_string_lossy().into_owned(),
            recovered.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(
            fs::read(&source_file).unwrap(),
            fs::read(recovered.join("1_TESTCOIN1.XPQ")).unwrap()
        );
        assert!(
            wallet_cash_recover(&[
                backup.to_string_lossy().into_owned(),
                recovered.to_string_lossy().into_owned(),
            ])
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cash_file_is_created_exclusively() {
        let path = std::env::temp_dir().join(format!(
            "wallet-cli-cash-{}-{}.XPQ",
            std::process::id(),
            unix_timestamp().unwrap()
        ));
        let _ = fs::remove_file(&path);
        write_new_synced_file(&path, b"cash recovery").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"cash recovery");
        assert!(write_new_synced_file(&path, b"overwrite").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn plaintext_wallet_roundtrips_with_secret_key() {
        let path = std::env::temp_dir().join(format!(
            "wallet-cli-plaintext-{}-{}.wallet.json",
            std::process::id(),
            unix_timestamp().unwrap()
        ));
        let _ = fs::remove_file(&path);
        let wallet = Wallet::generate();
        let secret_hex = hex::encode(wallet.secret_key.0);
        save_wallet(path.to_str().unwrap(), &wallet).unwrap();

        let bytes = fs::read(&path).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json.get("secret_key").and_then(serde_json::Value::as_str),
            Some(secret_hex.as_str())
        );

        let loaded = load_wallet(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.address, wallet.address);
        assert_eq!(loaded.public_key, wallet.public_key);
        assert_eq!(loaded.secret_key, wallet.secret_key);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn wallet_loading_accepts_plaintext() {
        let path = std::env::temp_dir().join(format!(
            "wallet-cli-plain-{}-{}.json",
            std::process::id(),
            unix_timestamp().unwrap()
        ));
        let wallet = Wallet::generate();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": WALLET_VERSION,
            "address": wallet.wallet_address(),
            "public_key": hex::encode(wallet.public_key.0),
            "secret_key": hex::encode(wallet.secret_key.0),
        }))
        .unwrap();
        write_new_synced_file(&path, &bytes).unwrap();

        let loaded = load_wallet(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.address, wallet.address);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn qcash_lookup_name_accepts_paths_and_rejects_unsafe_segments() {
        assert_eq!(
            qcash_lookup_name("./cash/100_E5D6217A74B06B8E.XPQ").unwrap(),
            "100_E5D6217A74B06B8E.XPQ"
        );
        assert_eq!(
            qcash_lookup_name("E5D6217A74B06B8E").unwrap(),
            "E5D6217A74B06B8E"
        );
        assert!(qcash_lookup_name("bad/name?x=1").is_err());
    }
}
