use paqus::{
    block::Nonce,
    consensus::supply::{Amount, XPQ},
    crypto::{
        Address, PublicKey, SecretKey, address_from_public_key, address_to_string,
        derive_public_key, generate_keypair, sign,
    },
    ledger::BLOCK_REWARD_MATURITY,
    transaction::{SignedTransaction, Transaction},
};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_RPC_ADDR: &str = "[2404:8000:1044:4d8:1202:b5ff:feb0:7020]:6666";
const RPC_ADDR_ENV: &str = "PAQUS_RPC_ADDR";
const DEFAULT_WALLET_PATH: &str = "wallet.json";
const DEFAULT_TRANSACTION_FEE: u64 = 1;
const DEFAULT_TRANSACTION_FEE_XPQ: &str = "0.01";
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
            println!("paqus-wallet {}", env!("CARGO_PKG_VERSION"));
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
        println!("6. RPC health");
        println!("7. RPC status");
        println!("8. RPC peers");
        println!("9. RPC chain");
        println!("10. Latest blocks");
        println!("11. Block by height");
        println!("12. Block by hash");
        println!("13. Transaction by hash");
        println!("14. Address explorer");
        println!("15. Accounts");
        println!("16. Mempool");
        println!("17. Hashrate");
        println!("18. Change RPC for this session");
        println!("19. Exit");
        println!("Type b/back to return from prompts.");

        let choice = prompt("Select")?;
        if choice == "19" {
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
            let wallet = load_wallet(&wallet_path)?;
            println!("{}", wallet.wallet_address());
            return Ok(true);
        }
        "3" => {
            let Some(wallet_path) = prompt_default_back("Wallet file path", DEFAULT_WALLET_PATH)?
            else {
                return Ok(false);
            };
            let rpc_addr = default_rpc_addr();
            let wallet = load_wallet(&wallet_path)?;
            print_rpc_get(&rpc_addr, &format!("/balance/{}", wallet.wallet_address()))?;
            return Ok(true);
        }
        "4" => {
            let rpc_addr = default_rpc_addr();
            print_global_stats(&rpc_addr)?;
            return Ok(true);
        }
        "5" => return menu_send_coin(),
        "6" => menu_rpc_get("/health")?,
        "7" => menu_rpc_get("/status")?,
        "8" => menu_rpc_get("/peers")?,
        "9" => menu_rpc_get("/chain")?,
        "10" => menu_rpc_get("/blocks/latest")?,
        "11" => {
            let Some(height) = prompt_back("Height")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/blocks/{height}"))?;
        }
        "12" => {
            let Some(hash) = prompt_back("Block hash")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/blocks/hash/{hash}"))?;
        }
        "13" => {
            let Some(hash) = prompt_back("Transaction hash")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/tx/{hash}"))?;
        }
        "14" => {
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
        "15" => menu_rpc_get("/accounts")?,
        "16" => menu_rpc_get("/mempool")?,
        "17" => menu_hashrate()?,
        "18" => {
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

fn menu_send_coin() -> Result<bool, String> {
    let Some(to) = prompt_back("Recipient address")? else {
        return Ok(false);
    };
    let Some(amount) = prompt_back("Amount XPQ")? else {
        return Ok(false);
    };
    let Some(fee) = prompt_default_back("Fee XPQ", DEFAULT_TRANSACTION_FEE_XPQ)? else {
        return Ok(false);
    };
    let Some(wallet_path) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
        return Ok(false);
    };
    let rpc_addr = default_rpc_addr();
    wallet_send_short(&[
        to,
        amount,
        "--fee".to_string(),
        fee,
        "--wallet".to_string(),
        wallet_path,
        "--rpc".to_string(),
        rpc_addr,
    ])?;
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
    print_amount_field("Target supply", value.get("target_supply"));
    print_amount_field("Current supply", value.get("current_supply"));
    print_amount_field("Genesis premine", value.get("genesis_premine"));
    print_amount_field("Mined supply", value.get("mined_supply"));
    print_amount_field("Max mined", value.get("max_mined_supply"));
    print_amount_field("Remaining", value.get("remaining_mined_supply"));
    println!();
    print_amount_field("Coinbase total", value.get("total_coinbase_rewards"));
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
        let total = amount_text(coinbase.get("total"));
        let to = short_value(coinbase.get("to"));
        print_field("Coinbase", format!("{total} to {to}"));
        print_amount_field("Fees", coinbase.get("fees"));
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
    print_field("Hash", short_value(value.get("hash")));
    print_field("From", short_value(value.get("from")));
    print_field("To", short_value(value.get("to")));
    print_amount_field("Amount", value.get("amount"));
    print_amount_field("Fee", value.get("fee"));
    print_field("Nonce", value_text(value.get("nonce")));
    print_field("Age", tx_age_text(value));
    print_field("Timestamp", value_text(value.get("timestamp")));
    print_field("Height", value_text(value.get("block_height")));
    print_field("Block", short_value(value.get("block_hash")));
    print_field("Status", str_value(value.get("status")));
}

fn print_field(label: &str, value: impl std::fmt::Display) {
    println!("{label:<13} : {value}");
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
    let whole = units / XPQ as u64;
    let fractional = units % XPQ as u64;
    format!("{}.{fractional:02} XPQ", format_grouped_u64(whole))
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
    let output_path = args.iter().find(|arg| !arg.starts_with('-'));
    let wallet = Wallet::generate();

    let address_str = wallet.wallet_address().to_string();
    let public_key_hex = hex::encode(wallet.public_key.0);
    let secret_key_hex = hex::encode(wallet.secret_key.0);

    if let Some(path) = output_path {
        let json_data = serde_json::json!({
            "address": address_str,
            "public_key": public_key_hex,
            "secret_key": secret_key_hex,
        });
        let json_str = serde_json::to_string_pretty(&json_data)
            .map_err(|error| format!("failed to serialize wallet: {error}"))?;
        fs::write(path, json_str)
            .map_err(|error| format!("failed to write wallet file `{path}`: {error}"))?;
        println!("Wallet successfully saved to `{path}`");
        println!("address: {address_str}");
        if show_secret {
            println!("secret_key: {secret_key_hex}");
        }
    } else {
        println!("address: {address_str}");
        println!("public_key: {public_key_hex}");
        if show_secret {
            println!("secret_key: {secret_key_hex}");
        } else {
            println!("secret_key: hidden (rerun with --show-secret to print it)");
        }
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
            value => return Err(format!("unknown wallet balance option `{value}`")),
        }
        index += 1;
    }

    let address = match address {
        Some(address) => address,
        None => load_wallet(&wallet_path)?.address,
    };

    println!(
        "{}",
        http_get(
            &rpc_addr,
            &format!("/balance/{}", address_to_string(&address))
        )?
    );
    Ok(())
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
        None => load_wallet(&wallet_path)?.address,
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
        let mut stats = Self::default();
        stats.mined_blocks = response.mined_blocks.len() as u64;
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
                fee = parse_amount(args.get(index), "--fee")?;
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
                fee = parse_amount(args.get(index), "--fee")?;
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
                fee = parse_amount(args.get(index), "--fee")?;
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
    let transaction =
        Transaction::new_at(wallet.address, to, amount, fee, nonce, unix_timestamp()?);
    let signed = wallet
        .sign_transaction(transaction)
        .map_err(|error| format!("failed to sign transaction: {error}"))?;
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
        .filter_map(|transaction| (transaction.from == address_hex).then_some(transaction.nonce))
        .collect::<Vec<_>>();
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
    from: String,
    nonce: u64,
}

#[derive(Debug, Deserialize)]
struct WalletFile {
    address: String,
    secret_key: String,
}

fn load_wallet(path: &str) -> Result<Wallet, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read wallet file {path}: {error}"))?;
    let wallet: WalletFile = serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse wallet file {path}: {error}"))?;
    let address = parse_address_hex(&wallet.address)?;
    let secret_key = parse_secret_key(Some(&wallet.secret_key))?;
    let wallet = Wallet::from_secret_key(secret_key);
    if wallet.address != address {
        return Err("wallet address does not match secret key".to_string());
    }
    Ok(wallet)
}

fn signed_transaction_to_hex(transaction: &SignedTransaction) -> Result<String, String> {
    Ok(hex::encode(transaction.to_bytes()))
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
        return Err("missing address hex".to_string());
    };
    parse_address_hex(value)
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
    load_wallet(DEFAULT_WALLET_PATH)
        .map(|wallet| wallet.wallet_address())
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
paqus-wallet

Usage:
  paqus-wallet
  paqus-wallet menu
  paqus-wallet new [wallet-path] [--show-secret]
  paqus-wallet address <secret-key-hex>
  paqus-wallet balance [address-hex] [--wallet path] [--rpc host:port]
  paqus-wallet stats [--rpc host:port]
  paqus-wallet address-stats [address-hex] [--wallet path] [--rpc host:port]
  paqus-wallet hashrate [--rpc host:port]
  paqus-wallet pay <address-hex> <amount-xpq> [--wallet path] [--fee xpq] [--rpc host:port]
  paqus-wallet send <address-hex> <amount-xpq> [--wallet path] [--nonce n] [--fee xpq] [--rpc host:port]
  paqus-wallet send [--wallet path] --to address-hex --amount xpq [--nonce n] [--fee xpq] [--submit] [--rpc host:port]

Defaults:
  Wallet path: wallet.json
  RPC address: $PAQUS_RPC_ADDR or [2404:8000:1044:4d8:1202:b5ff:feb0:7020]:6666
"
    );
}
