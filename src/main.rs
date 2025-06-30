use axum::{extract::Path, routing::get, Json, Router};
use serde_json::json;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::net::SocketAddr;

async fn root_handler() -> Json<serde_json::Value> {
    Json(json!({
        "message" : "Welcome to the Solana RPC API",
        "endpoints": [
            { "method": "GET", "path": "/account/:pubkey", "description": "Get account information by public key" },
            { "method": "GET", "path": "/block/:block", "description": "Get block information by block number" }
        ]
    }))
}

async fn balance_handler(Path(pubkey): Path<String>) -> Json<serde_json::Value> {
    let rpc_client = RpcClient::new("https://api.devnet.solana.com".to_string());
    let pubkey = pubkey.parse::<Pubkey>().unwrap();
    let lamports = rpc_client.get_balance(&pubkey).unwrap_or(0);
    let sol = lamports as f64 / 1_000_000_000.0; // Convert lamports to SOL
    Json(json!({
        "pubkey": pubkey.to_string(),
        "balance": sol,
    }))
}

async fn airdrop_handler(Path(pubkey): Path<String>) -> Json<serde_json::Value> {
    let rpc_client = RpcClient::new("https://api.devnet.solana.com".to_string());
    let pubkey = pubkey.parse::<Pubkey>().unwrap();
    let signature = rpc_client.request_airdrop(&pubkey, 1_000_000_000).unwrap();

    Json(json!({
        "pubkey": pubkey.to_string(),
        "signature": signature.to_string(),
        "message": "Airdrop successful"
    }))
}

async fn block_handler(Path(block): Path<u64>) -> Json<serde_json::Value> {
    let rpc_client = RpcClient::new("https://api.devnet.solana.com".to_string());
    let block = rpc_client.get_block(block).unwrap();

    Json(json!({
        "block": block.blockhash,
        "transactions": block.transactions.len(),
        "block_time": block.block_time
    }))
}

async fn details_handler(Path(pubkey): Path<String>) -> Json<serde_json::Value> {
    let rpc_client = RpcClient::new("https://api.devnet.solana.com".to_string());
    let pubkey = pubkey.parse::<Pubkey>().unwrap();
    let account_info = rpc_client.get_account(&pubkey).unwrap();

    Json(json!({
        "pubkey": pubkey.to_string(),
        "lamports": account_info.lamports,
        "owner": account_info.owner.to_string(),
        "data_length": account_info.data.len(),
        "executable": account_info.executable,
        "rent_epoch": account_info.rent_epoch
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/account/:pubkey", get(balance_handler))
        .route("/airdrop/:pubkey", get(airdrop_handler))
        .route("/block/:block", get(block_handler))
        .route("/details/:pubkey", get(details_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));

    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
