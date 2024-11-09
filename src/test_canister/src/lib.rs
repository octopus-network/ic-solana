use candid::Principal;

use ic_solana::compute_budget::compute_budget::Priority;
use ic_solana::metaplex::create_fungible_ix::create_fungible_ix;

use serde_bytes::ByteBuf;

use std::cell::RefCell;
use std::str::FromStr;

use ic_cdk::update;
use ic_solana::metaplex::types::FungibleFields;
use ic_solana::token::{SolanaClient, TokenInfo};
use ic_solana::types::Pubkey;
pub mod extension;
pub mod instruction_error;
pub mod program_error;
pub mod program_option;
pub mod serialization;
// pub mod system_instruction;
use ic_solana::token::system_instruction;
pub mod token_error;
use ic_solana::token::associated_account::create_associated_token_account;
use ic_solana::token::associated_account::get_associated_token_address_with_program_id;
use ic_solana::token::constants::{token22_program_id, token_program_id};
use ic_solana::token::token_instruction;
mod utils;
use ic_canister_log::log;
use ic_solana::eddsa::{hash_with_sha256, KeyType};
use ic_solana::ic_log::DEBUG;
use ic_solana::metaplex::create_fungible_ix::CreateFungibleArgs;
use ic_solana::rpc_client::RpcError;
use ic_solana::rpc_client::RpcResult;
use serde::Serialize;
use std::time::Duration;
pub const DELAY: u64 = 60;
pub const KEY_TYPE_NAME: &str = "Native";
mod memory;

use candid::Deserialize;
use ic_stable_structures::StableBTreeMap;
use memory::Memory;

#[derive(Serialize, Deserialize)]
struct State {
    // The seeds for the keys are stored in a stable memory.
    #[serde(skip, default = "init_stable_data")]
    seeds: StableBTreeMap<String, [u8; 64], Memory>,
}

fn init_stable_data() -> StableBTreeMap<String, [u8; 64], Memory> {
    StableBTreeMap::init(crate::memory::get_seeds())
}
impl Default for State {
    fn default() -> Self {
        Self {
            seeds: init_stable_data(),
        }
    }
}

thread_local! {
    static SOL_PROVIDER_CANISTER: RefCell<Option<Principal>>  = const { RefCell::new(None) };
    static STATE: RefCell<State> = RefCell::new(State::default());
    // static SCHNORR_CANISTER: RefCell<Option<Principal>> = const { RefCell::new(None)};
}

fn sol_canister_id() -> Principal {
    SOL_PROVIDER_CANISTER
        .with_borrow(|canister| canister.expect("Solana provider canister not initialized"))
}

async fn get_random_seed() -> [u8; 64] {
    match ic_cdk::api::management_canister::main::raw_rand().await {
        Ok(rand) => {
            let mut rand = rand.0;
            rand.extend(rand.clone());
            let rand: [u8; 64] = rand.try_into().expect("Expected a Vec of length 64");
            rand
        }
        Err(err) => {
            ic_cdk::trap(format!("Error getting random seed: {:?}", err).as_str());
        }
    }
}

#[ic_cdk::init]
async fn init(sol_canister: String) {
    SOL_PROVIDER_CANISTER.with(|canister| {
        *canister.borrow_mut() =
            Some(Principal::from_text(sol_canister).expect("Invalid principal"));
    });

    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::spawn(async move {
            let seed = get_random_seed().await;
            STATE.with(|s| {
                let seeds = &mut s.borrow_mut().seeds;
                seeds
                    .get(&KEY_TYPE_NAME.to_string())
                    .or_else(|| seeds.insert(KEY_TYPE_NAME.to_string(), seed));
            });
        });
    });
}

#[update]
async fn query_transaction(payer: String, tx_hash: String) -> String {
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: Pubkey::from_str(payer.as_str()).unwrap(),
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };
    let r = s.query_transaction(tx_hash, None).await.unwrap();
    r
}

#[update]
async fn get_payer(key_type: KeyType) -> String {
    let key_type = match key_type {
        KeyType::ChainKey => key_type,
        KeyType::Native(_) => {
            let seed = STATE.with(|s| {
                s.borrow()
                    .seeds
                    .get(&KEY_TYPE_NAME.to_string())
                    .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
            });
            KeyType::Native(seed.to_vec())
        }
    };

    let c = SolanaClient::derive_account(
        key_type,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    c.to_string()
}

#[update]
async fn create_token_with_metaplex(token_info: TokenInfo) -> String {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let derive_path = hash_with_sha256(token_info.token_id.clone().as_str());
    let token_mint =
        SolanaClient::derive_account(key_type.to_owned(), s.chainkey_name.clone(), derive_path)
            .await;
    let r = s
        .create_mint_with_metaplex(token_mint, token_info)
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn create_token_with_metaplex_delay(token_info: TokenInfo, delay: u64) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };
    let derive_path = hash_with_sha256(token_info.token_id.clone().as_str());

    //mock delay
    let delay = Duration::from_secs(delay);
    use std::sync::{Arc, Mutex};
    let token_mint = Arc::new(
        SolanaClient::derive_account(KeyType::ChainKey, s.chainkey_name.clone(), derive_path).await,
    );
    let blockhash = Arc::new(s.get_latest_blockhash().await.unwrap());
    let ret = Arc::new(Mutex::new(String::default()));
    let token_mint_clone = Arc::clone(&token_mint);
    let blockhash_clone = Arc::clone(&blockhash);
    let ret_clone = Arc::clone(&ret);

    ic_cdk_timers::set_timer(delay, move || {
        let token_mint = Arc::clone(&token_mint_clone);
        let blockhash = Arc::clone(&blockhash_clone);
        let ret = Arc::clone(&ret_clone);

        ic_cdk::spawn(async move {
            log!(
                DEBUG,
                "[solana_client::create_token_with_metaplex_delay] {}s delay  is over !",
                DELAY
            );
            let r = s
                .test_create_mint_with_metaplex(
                    *Arc::clone(&token_mint),
                    token_info.clone(),
                    *Arc::clone(&blockhash),
                )
                .await
                .unwrap();
            // let mut ret_lock = ret.lock().unwrap();
            *ret.lock().unwrap() = r;
            log!(
                DEBUG,
                "[solana_client::create_token_with_metaplex_delay] test_create_mint_with_metaplex resuslt: {:?}",
                ret
            );
        });
    });
    let resp = ret.lock().unwrap().clone();
    resp
}

#[update]
async fn create_ata(wallet: String, token_mint: String) -> String {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let to_account = Pubkey::from_str(wallet.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let r = s
        .create_associated_token_account(&to_account, &token_mint, &token_program_id())
        .await
        .unwrap();
    r
}

#[update]
async fn mint_to(wallet: String, amount: u64, token_mint: String) -> String {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let to_account = Pubkey::from_str(wallet.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let associated_account =
        get_associated_token_address_with_program_id(&to_account, &token_mint, &token_program_id());

    let r = s
        .mint_to(associated_account, amount, token_mint, token_program_id())
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn update_token_with_metaplex(token_mint: String, token_info: TokenInfo) -> String {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let token_mint = Pubkey::from_str(&token_mint).unwrap();
    let r = s
        .update_with_metaplex(token_mint, token_info)
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn create_token22_with_metaplex(token_info: TokenInfo) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };

    let derive_path = hash_with_sha256(token_info.token_id.clone().as_str());
    let token_mint =
        SolanaClient::derive_account(KeyType::ChainKey, s.chainkey_name.clone(), derive_path).await;
    let r = s
        .create_mint22_with_metaplex(token_mint, token_info)
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn create_token22() -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };
    let token_info = TokenInfo {
        token_id: "Runes•Omnity•Bitcion".to_string(),
        name: "Runes•Omnity•Bitcion".to_string(),
        symbol: "OT".to_string(),
        decimals: 2,
        uri: "".to_string(),
    };
    let r = s.create_mint22(token_info).await.unwrap();
    r.to_string()
}

#[update]
async fn create_token22_with_metadata(token_info: TokenInfo) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let mint_account = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        token_info.name.to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };

    let r = s
        .create_mint22_with_metadata(mint_account, token_info)
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn create_ata22_with_payer(payer_addr: String, wallet: String, token_mint: String) -> String {
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: Pubkey::from_str(payer_addr.as_str()).unwrap(),
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };
    let to_account = Pubkey::from_str(wallet.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let r = s
        .create_associated_token_account(&to_account, &token_mint, &token22_program_id())
        .await
        .unwrap();
    r
}

#[update]
async fn create_ata22(wallet: String, token_mint: String) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };
    let to_addr = Pubkey::from_str(&wallet).unwrap();
    let token_mint = Pubkey::from_str(&token_mint).unwrap();
    let r = s
        .create_associated_token_account(&to_addr, &token_mint, &token22_program_id())
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn mint22_to(wallet: String, amount: u64, token_mint: String) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };

    let to_account = Pubkey::from_str(wallet.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let associated_account = get_associated_token_address_with_program_id(
        &to_account,
        &token_mint,
        &token22_program_id(),
    );

    let r = s
        .mint_to(associated_account, amount, token_mint, token22_program_id())
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn update_token22_metadata(token_mint: String, token_info: TokenInfo) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let token_mint = Pubkey::from_str(&token_mint).unwrap();

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };

    let r = s
        .update_token22_metadata(token_mint, token_info)
        .await
        .unwrap();
    r.to_string()
}

#[ic_cdk::update]
async fn transfer_to(wallet: String, amount: u64) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };
    let to_account = Pubkey::from_str(&wallet).unwrap();
    let response = s.transfer_to(to_account, amount).await;

    let signature = response.unwrap();
    ic_cdk::println!("Signature: {:?}", signature);
    signature
}

#[update]
async fn close_mint_account(close_account: String, dest_account: String) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };

    let token_mint = Pubkey::from_str(close_account.as_str()).unwrap();
    let destination_account = Pubkey::from_str(dest_account.as_str()).unwrap();

    let r = s
        .close_account(token_program_id(), token_mint, destination_account)
        .await
        .unwrap();
    r.to_string()
}

#[update]
async fn freeze_mint_account(freeze_account: String, token_mint: String) -> String {
    let c = SolanaClient::derive_account(
        KeyType::ChainKey,
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: KeyType::ChainKey,
    };

    let destination_account = Pubkey::from_str(freeze_account.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let r = s
        .freeze_account(token_program_id(), token_mint, destination_account)
        .await
        .unwrap();
    r.to_string()
}

#[ic_cdk::update]
async fn get_compute_units_4_create_mint(token_info: TokenInfo) -> RpcResult<Option<u64>> {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let token_mint = SolanaClient::derive_account(
        key_type.to_owned(),
        s.chainkey_name.clone(),
        token_info.token_id.to_string(),
    )
    .await;
    let metadata = FungibleFields {
        name: token_info.name,
        symbol: token_info.symbol,
        uri: token_info.uri,
    };
    let create_arg = CreateFungibleArgs {
        mint: token_mint,
        metadata,
        immutable: false,
        decimals: token_info.decimals,
        payer: s.payer.to_owned(),
    };
    let instructions = vec![create_fungible_ix(create_arg)];

    let units = s
        .get_compute_units(
            instructions.as_slice(),
            vec![
                s.payer_derive_path.clone(),
                vec![ByteBuf::from(token_info.token_id.clone())],
            ],
            s.key_type.to_owned(),
        )
        .await
        .map_err(|e| RpcError::Text(e.to_string()))?;

    ic_cdk::println!("get_compute_units for create_fungible_ix : {:?}", units);
    Ok(units)
}

#[ic_cdk::update]
async fn get_compute_units_4_create_ata(
    wallet: String,
    token_mint: String,
) -> RpcResult<Option<u64>> {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let to_account = Pubkey::from_str(wallet.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();

    let instructions = vec![create_associated_token_account(
        &s.payer,
        &to_account,
        &token_mint,
        &token_program_id(),
    )];

    let units = s
        .get_compute_units(
            instructions.as_slice(),
            vec![s.payer_derive_path.clone()],
            s.key_type.to_owned(),
        )
        .await
        .map_err(|e| RpcError::Text(e.to_string()))?;

    ic_cdk::println!(
        "get_compute_units for create_associated_token_account : {:?}",
        units
    );
    Ok(units)
}

#[ic_cdk::update]
async fn get_compute_units_4_mint_to(
    wallet: String,
    amount: u64,
    token_mint: String,
) -> RpcResult<Option<u64>> {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let wallet_account = Pubkey::from_str(wallet.as_str()).unwrap();
    let token_mint = Pubkey::from_str(token_mint.as_str()).unwrap();
    // let associated_account =
    //     get_associated_token_address_with_program_id(&wallet_account, &token_mint, &token_program_id());
    let associated_account = wallet_account;

    let instructions = vec![token_instruction::mint_to(
        &token_program_id(),
        &token_mint,
        &associated_account,
        &s.payer,
        &[],
        amount,
    )];

    let units = s
        .get_compute_units(
            instructions.as_slice(),
            vec![s.payer_derive_path.clone()],
            s.key_type.to_owned(),
        )
        .await
        .map_err(|e| RpcError::Text(e.to_string()))?;

    ic_cdk::println!(
        "get_compute_units for system_instruction::transfer : {:?}",
        units
    );
    Ok(units)
}

#[ic_cdk::update]
async fn get_compute_units_4_transfer(wallet: String, amount: u64) -> RpcResult<Option<u64>> {
    let seed = STATE.with(|s| {
        s.borrow()
            .seeds
            .get(&KEY_TYPE_NAME.to_string())
            .unwrap_or_else(|| panic!("No key with name {:?}", &KEY_TYPE_NAME.to_string()))
    });
    let key_type = KeyType::Native(seed.to_vec());
    let c = SolanaClient::derive_account(
        key_type.to_owned(),
        "dfx_test_key".to_string(),
        "custom_payer".to_string(),
    )
    .await;

    let s = SolanaClient {
        sol_canister_id: sol_canister_id(),
        payer: c,
        payer_derive_path: vec![ByteBuf::from("custom_payer")],
        chainkey_name: "dfx_test_key".to_string(),
        forward: None,
        priority: Some(Priority::None),
        key_type: key_type.to_owned(),
    };

    let to_account = Pubkey::from_str(&wallet).unwrap();
    let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
        s.sol_canister_id,
        "sol_getBalance",
        (to_account.to_string(), s.forward.to_owned()),
    )
    .await;

    let lamports = response.unwrap().0?;

    let fee = 10_000;

    if lamports <= amount + fee {
        ic_cdk::trap("Not enough lamports");
    }

    let instructions = vec![system_instruction::transfer(&s.payer, &to_account, amount)];

    let units = s
        .get_compute_units(
            instructions.as_slice(),
            vec![s.payer_derive_path.clone()],
            s.key_type.to_owned(),
        )
        .await
        .map_err(|e| RpcError::Text(e.to_string()))?;

    ic_cdk::println!(
        "get_compute_units for system_instruction::transfer : {:?}",
        units
    );
    Ok(units)
}

ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    // use super::system_instruction::SystemInstruction;
    use bincode::Options;
    use serde_json::{from_str, json, Value};
    use solana_program::system_instruction::SystemInstruction;
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
