use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{Signer, keypair::Keypair},
};
use spl_token::instruction::{initialize_mint, mint_to};
use std::{net::SocketAddr, str::FromStr};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct Account {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<Account>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn generate_keypair_handler() -> Json<ApiResponse<KeypairData>> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();

    Json(ApiResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    })
}

async fn create_token_handler(
    Json(payload): Json<CreateTokenRequest>,
) -> Json<ApiResponse<InstructionData>> {
    let mint_pubkey = Pubkey::from_str(&payload.mint).unwrap();
    let mint_authority_pubkey = Pubkey::from_str(&payload.mint_authority).unwrap();

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        payload.decimals,
    )
    .unwrap();

    let accounts: Vec<Account> = instruction
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Json(ApiResponse {
        success: true,
        data: InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    })
}

async fn mint_token_handler(
    Json(payload): Json<MintTokenRequest>,
) -> Json<ApiResponse<InstructionData>> {
    let mint_pubkey = Pubkey::from_str(&payload.mint).unwrap();
    let destination_pubkey = Pubkey::from_str(&payload.destination).unwrap();
    let authority_pubkey = Pubkey::from_str(&payload.authority).unwrap();

    let instruction = mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        payload.amount,
    )
    .unwrap();

    let accounts: Vec<Account> = instruction
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    Json(ApiResponse {
        success: true,
        data: InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair_handler))
        .route("/token/create", post(create_token_handler))
        .route("/token/mint", post(mint_token_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));

    println!("Listening on http://{}", addr);
    println!("Available endpoints:");
    println!("  POST /keypair - Generate a new Solana keypair");
    println!("  POST /token/create - Create a new SPL token");
    println!("  POST /token/mint - Mint SPL tokens");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
