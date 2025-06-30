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
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint address".to_string()),
                }),
            );
        }
    };

    let mint_authority_pubkey = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint authority address".to_string()),
                }),
            );
        }
    };

    let instruction = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        payload.decimals,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to create token instruction".to_string()),
                }),
            );
        }
    };

    let accounts: Vec<Account> = instruction
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
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint address".to_string()),
                }),
            );
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid destination address".to_string()),
                }),
            );
        }
    };

    let authority_pubkey = match Pubkey::from_str(&payload.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid authority address".to_string()),
                }),
            );
        }
    };

    let instruction = match mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        payload.amount,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to create mint instruction".to_string()),
                }),
            );
        }
    };

    let accounts: Vec<Account> = instruction
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
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Missing required fields".to_string()),
            }),
        );
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid secret key format".to_string()),
                }),
            );
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid secret key".to_string()),
                }),
            );
        }
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

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
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Missing required fields".to_string()),
            }),
        );
    }

    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid public key format".to_string()),
                }),
            );
        }
    };

    let pubkey = match Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid public key".to_string()),
                }),
            );
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid signature format".to_string()),
                }),
            );
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(signature) => signature,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid signature".to_string()),
                }),
            );
        }
    };

    let message_bytes = payload.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);

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
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid from address".to_string()),
                }),
            );
        }
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid to address".to_string()),
                }),
            );
        }
    };

    if payload.lamports == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Amount must be greater than 0".to_string()),
            }),
        );
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
    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid destination address".to_string()),
                }),
            );
        }
    };

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint address".to_string()),
                }),
            );
        }
    };

    let owner_pubkey = match Pubkey::from_str(&payload.owner) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid owner address".to_string()),
                }),
            );
        }
    };

    if payload.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Amount must be greater than 0".to_string()),
            }),
        );
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
        Ok(instruction) => instruction,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to create token transfer instruction".to_string()),
                }),
            );
        }
    };

    let accounts: Vec<TokenAccount> = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
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
