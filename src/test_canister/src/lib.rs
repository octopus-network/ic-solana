use candid::{CandidType, Principal};

use ic_management_canister_types::{
    DerivationPath, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs, SchnorrPublicKeyResponse,
    SignWithSchnorrArgs, SignWithSchnorrReply,
};
use ic_solana::request::RpcRequest;
use ic_solana::rpc_client::RpcResult;
use ic_solana::types::{AccountMeta, BlockHash, Instruction, Pubkey};

use serde_bytes::ByteBuf;

use std::cell::RefCell;
use std::str::FromStr;
use ic_cdk::update;

pub mod instruction_error;
pub mod program_error;
pub mod system_instruction;
mod instruction;

thread_local! {
    static SOL_PROVIDER_CANISTER: RefCell<Option<Principal>>  = const { RefCell::new(None) };
}

fn sol_canister_id() -> Principal {
    SOL_PROVIDER_CANISTER
        .with_borrow(|canister| canister.expect("Solana provider canister not initialized"))
}

#[derive(CandidType, Debug)]
pub struct SendTransactionRequest {
    pub instructions: Vec<String>,
    pub recent_blockhash: Option<String>,
}

// test ic-solana-provider request
#[ic_cdk::update]
pub async fn request() {
    let sol_canister = sol_canister_id();
    // Get the solana address associated with the caller
    let response: Result<(String,), _> = ic_cdk::call(sol_canister, "get_address", ()).await;
    let solana_address = Pubkey::from_str(&response.unwrap().0).unwrap();
    ic_cdk::println!("solana_address: {}", solana_address);

    let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
        sol_canister,
        "request",
        (
            RpcRequest::GetMinimumBalanceForRentExemption.to_string(),
            "[82]",
            156u64,
        ),
    )
    .await;
    let rent_exemption = response.unwrap().0.unwrap();
    ic_cdk::println!("rent_exemption: {:?}", rent_exemption);
}

// test transfer
#[ic_cdk::update]
pub async fn transfer() {
    let sol_canister = sol_canister_id();

    // Get the solana address associated with the caller
    let response: Result<(String,), _> = ic_cdk::call(sol_canister, "get_address", ()).await;
    let solana_address = Pubkey::from_str(&response.unwrap().0).unwrap();
    ic_cdk::println!("solana_address: {}", solana_address);

    // Get the balance
    let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
        sol_canister,
        "sol_getBalance",
        (solana_address.to_string(),),
    )
    .await;
    let lamports = response.unwrap().0.unwrap();
    ic_cdk::println!("Balance: {} lamports", lamports);

    let fee = 10_000;
    let amount = 1_000_000u64;

    if lamports <= amount + fee {
        ic_cdk::trap("Not enough lamports");
    }

    // Get the latest blockhash
    let response: Result<(RpcResult<String>,), _> =
        ic_cdk::call(sol_canister, "sol_latestBlockhash", ()).await;
    let blockhash = BlockHash::from_str(&response.unwrap().0.unwrap()).unwrap();
    ic_cdk::println!("Latest Blockhash: {:?}", blockhash);

    // Generate a transfer instruction
    let system_program_id = Pubkey::from_str("11111111111111111111111111111111").unwrap();
    let transfer_ix1 = Instruction::new_with_bincode(
        system_program_id,
        &(2, 0, 0, 0, 40, 54, 89, 0, 0, 0, 0, 0), // transfer 9_000_000 lamports
        vec![
            AccountMeta::new(solana_address, true),
            AccountMeta::new(
                Pubkey::from_str("AAAAUrmaZWvna6vHndc5LoVWUBmnj9sjxnvPz5U3qZGY").unwrap(),
                false,
            ),
            AccountMeta::new(system_program_id, false),
        ],
    );
    let to_pubkey = Pubkey::from_str("AAAAUrmaZWvna6vHndc5LoVWUBmnj9sjxnvPz5U3qZGY").unwrap();
    let transfer_ix2 = system_instruction::transfer(&solana_address, &to_pubkey, 9_000_000);

    let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
        sol_canister,
        "sol_sendTransaction",
        (SendTransactionRequest {
            instructions: vec![transfer_ix1.to_string(), transfer_ix2.to_string()],
            recent_blockhash: Some(blockhash.to_string()),
        },),
    )
    .await;

    let signature = response.unwrap().0.unwrap();
    ic_cdk::println!("Signature: {:?}", signature);
}

#[update]
async fn get_chainkey() -> String{

    let sol_canister = sol_canister_id();
    // Get the solana address associated with the caller
    let response: Result<(String,), _> = ic_cdk::call(sol_canister, "get_address", ()).await;
    let custom_address = Pubkey::from_str(&response.unwrap().0).unwrap();
    custom_address.to_string()
}

// test create mint account and init it
#[ic_cdk::update]
async fn create_mint_account() {
    let sol_canister = sol_canister_id();
    // Get the solana address associated with the caller
    let response: Result<(String,), _> = ic_cdk::call(sol_canister, "get_address", ()).await;
    let custom_address = Pubkey::from_str(&response.unwrap().0).unwrap();

    ic_cdk::println!("solana_address: {}", custom_address);
    let space: usize = 82;
    let decimals = 9u8;

    // get rent exemption
    let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
        sol_canister,
        "sol_getminimumbalanceforrentexemption",
        (space,),
    )
    .await;
    let rent_exemption = response.unwrap().0.unwrap();
    ic_cdk::println!("rent_exemption: {:?}", rent_exemption);

    let token22_program_id =
        Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap();

    // gen token pubkey,or mint account pubkey
    let key_name = "test_key_1".to_string();
    let cur_canister_id = ic_cdk::id();
    let token_pubkey_derived_path = vec![ByteBuf::from(cur_canister_id.as_slice())];
    let token_mint = Pubkey::try_from(
        eddsa_public_key(key_name.clone(), token_pubkey_derived_path.clone()).await,
    )
    .unwrap();
    ic_cdk::println!("token_pubkey: {:?}", token_mint);

    // build create account instruction
    let mut instructions = vec![system_instruction::create_account(
        &custom_address,
        &token_mint,
        rent_exemption,
        space as u64,
        &token22_program_id,
    )];
    ic_cdk::println!("create_account_ix: {:?}", instructions);

    // TODO: build init account instruction
    instructions.push(
        instruction::initialize_mint(
            &token22_program_id,
            &token_mint,
            &custom_address,
            None,
            decimals).unwrap()
    );
    let response: Result<(RpcResult<String>,), _> =
        ic_cdk::call(sol_canister, "sol_latestBlockhash", ()).await;
    let blockhash = BlockHash::from_str(&response.unwrap().0.unwrap()).unwrap();
    let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
        sol_canister,
        "sol_sendTransaction",
        (SendTransactionRequest {
            instructions: vec![instructions[0].to_string(), instructions[1].to_string()],
            recent_blockhash: Some(blockhash.to_string()),
        },),
    )
        .await;
    let signature = response.unwrap().0.unwrap();
    ic_cdk::println!("Signature: {:?}", signature);

}

// test mint token to dest address
#[ic_cdk::update]
async fn mint_to() {


}


#[update]
async fn get_last_block_hash() -> String {
    let sol_canister = sol_canister_id();
    let response: Result<(RpcResult<String>,), _> =
        ic_cdk::call(sol_canister, "sol_latestBlockhash", ()).await;
    response.unwrap().0.unwrap()
}
/// When setting up the test canister, we need to save a reference to the solana provider canister
/// so that we can call it later.
#[ic_cdk::init]
async fn init(sol_canister: String) {
    SOL_PROVIDER_CANISTER.with(|canister| {
        *canister.borrow_mut() =
            Some(Principal::from_text(sol_canister).expect("Invalid principal"));
    });
}

/// Fetches the ed25519 public key from the schnorr canister.
pub async fn eddsa_public_key(key_name: String, derivation_path: Vec<ByteBuf>) -> Vec<u8> {
    let schnorr_canister = Principal::from_text("bkyz2-fmaaa-aaaaa-qaaaq-cai").unwrap();

    let res: Result<(SchnorrPublicKeyResponse,), _> = ic_cdk::call(
        schnorr_canister,
        "schnorr_public_key",
        (SchnorrPublicKeyArgs {
            canister_id: None,
            derivation_path: DerivationPath::new(derivation_path),
            key_id: SchnorrKeyId {
                algorithm: SchnorrAlgorithm::Ed25519,
                name: key_name,
            },
        },),
    )
    .await;

    res.unwrap().0.public_key
}

/// Signs a message with an ed25519 key.
pub async fn sign_with_eddsa(
    key_name: String,
    derivation_path: Vec<ByteBuf>,
    message: Vec<u8>,
) -> Vec<u8> {
    let schnorr_canister = Principal::from_text("bkyz2-fmaaa-aaaaa-qaaaq-cai").unwrap();

    let res: Result<(SignWithSchnorrReply,), _> = ic_cdk::call(
        schnorr_canister,
        "sign_with_schnorr",
        (SignWithSchnorrArgs {
            message,
            derivation_path: DerivationPath::new(derivation_path),
            key_id: SchnorrKeyId {
                name: key_name,
                algorithm: SchnorrAlgorithm::Ed25519,
            },
        },),
    )
    .await;

    res.unwrap().0.signature
}

ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    use bincode::Options;
    use serde_json::{from_str, json, Value};
    use spl_token_2022::instruction::TokenInstruction;
    use spl_token_2022::solana_program::{program_option::COption, pubkey::Pubkey};

    use crate::system_instruction::SystemInstruction;
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
    }
}
