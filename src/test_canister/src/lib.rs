use candid::Principal;

use serde_bytes::ByteBuf;

use std::cell::RefCell;
use std::str::FromStr;

use ic_cdk::update;

use ic_solana::token::{SolanaClient, TokenInfo};
use ic_solana::types::Pubkey;
pub mod extension;
pub mod instruction_error;
pub mod program_error;
pub mod program_option;
pub mod serialization;
pub mod system_instruction;
pub mod token_error;
pub mod token_instruction;

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
async fn query_transaction(payer: String, tx_hash: String) -> String {
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
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    c.to_string()
}

#[update]
async fn create_token() -> String {
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let token_info = TokenInfo {
        name: "YHTX".to_string(),
        symbol: "YHTX".to_string(),
        decimals: 2,
        uri: "".to_string(),
    };
    let r = s.create_mint(token_info).await.unwrap();
    r.to_string()
}

#[update]
async fn create_token_with_metadata(token_info: TokenInfo) -> String {
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    // let token_info = TokenInfo {
    //     name: "YHTCC".to_string(),
    //     symbol: "YHTCC".to_string(),
    //     decimals: 2,
    //     uri: "".to_string(),
    // };
    let r = s.create_mint_with_metadata(token_info).await.unwrap();
    r.to_string()
}

#[update]
async fn create_associated_token_account(
    payer_addr: String,
    to_account: String,
    token_mint: String,
) -> String {
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: Pubkey::from_str(payer_addr.as_str()).unwrap(),
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let to_account = Pubkey::from_str(to_account.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let r = s
        .create_associated_token_account(&to_account, &token_mint)
        .await
        .unwrap();
    r
}

#[update]
async fn create_ata(to_address: String, token_mint: String) -> String {
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let to_addr = Pubkey::from_str(&to_address).unwrap();
    let token_mint = Pubkey::from_str(&token_mint).unwrap();
    let r = s.associated_account(&to_addr, &token_mint).await.unwrap();
    r.to_string()
}

#[update]
async fn mint_to(to_account: String, amount: u64, token_mint: String) -> String {
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };

    let to_account = Pubkey::from_str(to_account.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let associated_account = s
        .associated_account(&to_account, &token_mint)
        .await
        .unwrap();

    let r = s
        .mint_to(associated_account, amount, token_mint)
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn update_token_metadata(token_mint: String, token_info: TokenInfo) -> String {
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let token_mint = Pubkey::from_str(&token_mint).unwrap();

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };

    let r = s.update_metadata(token_mint, token_info).await.unwrap();
    r.to_string()
}
#[ic_cdk::update]
async fn transfer_to(to_account: String, amount: u64) -> String {
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "test_key_1".to_string(),
        schnorr_canister: schnorr_canister(),
    };
    let to_account = Pubkey::from_str(&to_account).unwrap();
    let response = s.transfer_to(to_account, amount).await;

    let signature = response.unwrap();
    ic_cdk::println!("Signature: {:?}", signature);
    signature
}
ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    use super::system_instruction::SystemInstruction;
    use bincode::Options;
    use serde_json::{from_str, json, Value};
    use spl_token_2022::instruction::TokenInstruction;
    use spl_token_2022::solana_program::{program_option::COption, pubkey::Pubkey};

    // use spl_token_2022::pod_instruction::PodTokenInstruction;

    #[test]
    fn test_requst_params() {
        let params = "[82,\"AAAAUrmaZWvna6vHndc5LoVWUBmnj9sjxnvPz5U3qZGY\"]".to_string();
        let parsed_params: Value = from_str(&params).expect("Failed to parse JSON");
        if let Value::Array(_) = parsed_params {
            println!("Parsed JSON is an array: {:?}", parsed_params);
        } else {
            println!("Parsed JSON is not an array");
        }
        let payload = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": &"getMinimumBalanceForRentExemption",
            "params": parsed_params
        }))
        .unwrap();
        println!("payload: {:?}", payload);
    }

    #[test]
    fn test_transfer_packing() {
        let transfer = SystemInstruction::Transfer {
            lamports: 1_000_000u64,
        };
        ic_cdk::println!("transfer: {:?}", transfer);
        let encoded_transfer = (2, 0, 0, 0, 64, 66, 15, 0, 0, 0, 0, 0);
        ic_cdk::println!("encoded_transfer: {:?}", encoded_transfer);
        // Define a custom bincode configuration that encodes as little-endian
        let encoded_transfer: Vec<u8> = bincode::options()
            .with_fixint_encoding()
            .serialize(&transfer)
            .unwrap();

        println!("transfer bincode: {:?}", encoded_transfer);
    }

    #[test]
    fn test_initialize_mint_packing() {
        let decimals = 2;
        let mint_authority = Pubkey::new_from_array([1u8; 32]);
        let freeze_authority = COption::None;
        let check = TokenInstruction::InitializeMint {
            decimals,
            mint_authority,
            freeze_authority,
        };
        let packed = check.pack();
        let mut expect = Vec::from([0u8, 2]);
        expect.extend_from_slice(&[1u8; 32]);
        expect.extend_from_slice(&[0]);
        assert_eq!(packed, expect);
        let unpacked = TokenInstruction::unpack(&expect).unwrap();
        assert_eq!(unpacked, check);
        // let instruction_type = decode_instruction_type::<TokenInstruction>(&packed).unwrap();
        // assert_eq!(instruction_type, PodTokenInstruction::InitializeMint);
        // let (pod, pod_freeze_authority) =
        //     decode_instruction_data_with_coption_pubkey::<InitializeMintData>(&packed).unwrap();
        // assert_eq!(pod.decimals, decimals);
        // assert_eq!(pod.mint_authority, mint_authority);
        // assert_eq!(pod_freeze_authority, freeze_authority.into());

        // let mint_authority = Pubkey::new_from_array([2u8; 32]);
        // let freeze_authority = COption::Some(Pubkey::new_from_array([3u8; 32]));
        // let check = TokenInstruction::InitializeMint {
        //     decimals,
        //     mint_authority,
        //     freeze_authority,
        // };
        // let packed = check.pack();
        // let mut expect = vec![0u8, 2];
        // expect.extend_from_slice(&[2u8; 32]);
        // expect.extend_from_slice(&[1]);
        // expect.extend_from_slice(&[3u8; 32]);
        // assert_eq!(packed, expect);
        // let unpacked = TokenInstruction::unpack(&expect).unwrap();
        // assert_eq!(unpacked, check);

        // let instruction_type = decode_instruction_type::<PodTokenInstruction>(&packed).unwrap();
        // assert_eq!(instruction_type, PodTokenInstruction::InitializeMint);
        // let (pod, pod_freeze_authority) =
        //     decode_instruction_data_with_coption_pubkey::<InitializeMintData>(&packed).unwrap();
        // assert_eq!(pod.decimals, decimals);
        // assert_eq!(pod.mint_authority, mint_authority);
        // assert_eq!(pod_freeze_authority, freeze_authority.into());
    }
}
