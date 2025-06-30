use axum::{Json, Router, http::StatusCode, routing::post};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::Signature,
    signer::{Signer, keypair::Keypair},
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::{net::SocketAddr, str::FromStr};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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

#[derive(Serialize)]
struct SolTransferData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenTransferData {
    program_id: String,
    accounts: Vec<TokenAccount>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
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

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

fn error<T>(msg: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }),
    )
}

async fn generate_keypair_handler() -> (StatusCode, Json<ApiResponse<KeypairData>>) {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(KeypairData { pubkey, secret }),
            error: None,
        }),
    )
}

async fn create_token_handler(
    Json(payload): Json<CreateTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionData>>) {
    if payload.mint.is_empty() || payload.mint_authority.is_empty() {
        return error("Missing required fields");
    }
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid mint address"),
    };
    let mint_authority_pubkey = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid mint authority address"),
    };
    let instruction = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        payload.decimals,
    ) {
        Ok(ix) => ix,
        Err(_) => return error("Failed to create token instruction"),
    };
    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(InstructionData {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&instruction.data),
            }),
            error: None,
        }),
    )
}

async fn mint_token_handler(
    Json(payload): Json<MintTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionData>>) {
    if payload.mint.is_empty() || payload.destination.is_empty() || payload.authority.is_empty() {
        return error("Missing required fields");
    }
    if payload.amount == 0 {
        return error("Amount must be greater than 0");
    }
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid mint address"),
    };
    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid destination address"),
    };
    let authority_pubkey = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid authority address"),
    };
    let instruction = match mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => return error("Failed to create mint instruction"),
    };
    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(InstructionData {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&instruction.data),
            }),
            error: None,
        }),
    )
}

async fn sign_message_handler(
    Json(payload): Json<SignMessageRequest>,
) -> (StatusCode, Json<ApiResponse<SignMessageData>>) {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return error("Missing required fields");
    }
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return error("Invalid secret key format"),
    };
    if secret_bytes.len() != 64 {
        return error("Invalid secret key length");
    }
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return error("Invalid secret key"),
    };
    let signature = keypair.sign_message(payload.message.as_bytes());
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(SignMessageData {
                signature: general_purpose::STANDARD.encode(signature.as_ref()),
                public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
                message: payload.message,
            }),
            error: None,
        }),
    )
}

async fn verify_message_handler(
    Json(payload): Json<VerifyMessageRequest>,
) -> (StatusCode, Json<ApiResponse<VerifyMessageData>>) {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return error("Missing required fields");
    }
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return error("Invalid public key format"),
    };
    if pubkey_bytes.len() != 32 {
        return error("Invalid public key length");
    }
    let pubkey = match Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid public key"),
    };
    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return error("Invalid signature format"),
    };
    if signature_bytes.len() != 64 {
        return error("Invalid signature length");
    }
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return error("Invalid signature"),
    };
    let is_valid = signature.verify(pubkey.as_ref(), payload.message.as_bytes());
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(VerifyMessageData {
                valid: is_valid,
                message: payload.message,
                pubkey: payload.pubkey,
            }),
            error: None,
        }),
    )
}

async fn send_sol_handler(
    Json(payload): Json<SendSolRequest>,
) -> (StatusCode, Json<ApiResponse<SolTransferData>>) {
    if payload.from.is_empty() || payload.to.is_empty() {
        return error("Missing required fields");
    }
    if payload.lamports == 0 {
        return error("Amount must be greater than 0");
    }
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid from address"),
    };
    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid to address"),
    };
    if from_pubkey == to_pubkey {
        return error("Cannot transfer to the same address");
    }
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);
    let accounts = vec![
        instruction.accounts[0].pubkey.to_string(),
        instruction.accounts[1].pubkey.to_string(),
    ];
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(SolTransferData {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&instruction.data),
            }),
            error: None,
        }),
    )
}

async fn send_token_handler(
    Json(payload): Json<SendTokenRequest>,
) -> (StatusCode, Json<ApiResponse<TokenTransferData>>) {
    if payload.destination.is_empty() || payload.mint.is_empty() || payload.owner.is_empty() {
        return error("Missing required fields");
    }
    if payload.amount == 0 {
        return error("Amount must be greater than 0");
    }
    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid destination address"),
    };
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid mint address"),
    };
    let owner_pubkey = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => return error("Invalid owner address"),
    };
    if owner_pubkey == destination_pubkey {
        return error("Cannot transfer to the same address");
    }
    let source_ata = get_associated_token_address(&owner_pubkey, &mint_pubkey);
    let dest_ata = get_associated_token_address(&destination_pubkey, &mint_pubkey);
    let instruction = match transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner_pubkey,
        &[],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => return error("Failed to create token transfer instruction"),
    };
    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer, // This will serialize as "isSigner"
        })
        .collect();
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: Some(TokenTransferData {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: general_purpose::STANDARD.encode(&instruction.data),
            }),
            error: None,
        }),
    )
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair_handler))
        .route("/token/create", post(create_token_handler))
        .route("/token/mint", post(mint_token_handler))
        .route("/message/sign", post(sign_message_handler))
        .route("/message/verify", post(verify_message_handler))
        .route("/send/sol", post(send_sol_handler))
        .route("/send/token", post(send_token_handler));
    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));
    println!("Server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
