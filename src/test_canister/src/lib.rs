use std::cell::RefCell;
use std::str::FromStr;

use candid::{CandidType, Principal};
use ic_cdk::update;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use ic_solana::token::{SolanaClient, TokenCreateInfo};
use ic_solana::types::{EncodedConfirmedTransactionWithStatusMeta, Pubkey};

mod utils;

thread_local! {
    static SOL_PROVIDER_CANISTER: RefCell<Option<Principal>>  = const { RefCell::new(None) };
    static SCHNORR_CANISTER: RefCell<Option<Principal>> = const { RefCell::new(None)};
}

fn sol_canister_id() -> Principal {
    SOL_PROVIDER_CANISTER
        .with_borrow(|canister| canister.expect("Solana provider canister not initialized"))
}

fn schnorr_canister() -> Principal {
    SCHNORR_CANISTER.with_borrow(|canister| canister.expect("schnorr canister no initialized"))
}

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Encoding {
    Binary, // Legacy. Retained for RPC backwards compatibility
    Base64,
    Base58,
    Json,
    JsonParsed,
}

#[ic_cdk::init]
async fn init(sol_canister: String, schnorr_canister: String) {
    SOL_PROVIDER_CANISTER.with(|canister| {
        *canister.borrow_mut() =
            Some(Principal::from_text(sol_canister).expect("Invalid principal"));
    });

    SCHNORR_CANISTER.with(|canister| {
        *canister.borrow_mut() =
            Some(Principal::from_text(schnorr_canister).expect("Invalid principal"));
    });
}

#[update]
async fn query_transaction(
    payer: String,
    tx_hash: String,
) -> EncodedConfirmedTransactionWithStatusMeta {
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: Pubkey::from_str(payer.as_str()).unwrap(),
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let r = s.query_transaction(tx_hash).await.unwrap();
    r
}

#[update]
async fn get_payer() -> String {
    let payer_path = vec![ByteBuf::from("custom_payer")];
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    c.to_string()
}

#[update]
async fn create_token_with_metadata(payer_addr: String) -> String {
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: Pubkey::from_str(payer_addr.as_str()).unwrap(),
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let token_info = TokenCreateInfo {
        name: "YHTCC".to_string(),
        symbol: "YHTCC".to_string(),
        decimals: 2,
        uri: "".to_string(),
    };
    let r = s.create_mint_with_metadata(token_info).await.unwrap();
    r.to_string()
}

#[update]
async fn create_token(payer_addr: String) -> String {
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: Pubkey::from_str(payer_addr.as_str()).unwrap(),
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let token_info = TokenCreateInfo {
        name: "YHTX".to_string(),
        symbol: "YHTX".to_string(),
        decimals: 2,
        uri: "".to_string(),
    };
    let r = s.create_mint(token_info).await.unwrap();
    r.to_string()
}

#[update]
async fn get_transaction(signature: String) {
    let payer = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: payer,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let r = s.query_transaction(signature).await.unwrap();
    ic_cdk::println!("transaction detail: {:?}", r);
    // serde_json::to_string(&r).unwrap()
}

ic_cdk::export_candid!();
