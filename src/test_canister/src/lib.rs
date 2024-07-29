use candid::{CandidType, Principal};

use ic_solana::token::associated_account::get_associated_token_address_with_program_id;
use ic_solana::token::constants::token22_program_id;
use serde_bytes::ByteBuf;

use std::cell::RefCell;
use std::str::FromStr;

use ic_cdk::update;

use ic_solana::token::{SolanaClient, TokenCreateInfo};
use ic_solana::types::{account, EncodedConfirmedTransactionWithStatusMeta, Pubkey};
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
    // let payer_path = vec![ByteBuf::from("custom_payer")];
    let c = SolanaClient::derive_account(
        schnorr_canister(),
        "test_key_1".to_string(),
        "custom_payer".to_string(),
    )
    .await;
    c.to_string()
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
async fn mint_to(
    payer_addr: String,
    to_account: String,
    amount: u64,
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
    let associated_account = get_associated_token_address_with_program_id(
        &to_account,
        &token_mint,
        &token22_program_id(),
    );

    ic_cdk::println!(
        "{:?} for {:?} associated token account: {:?} ",
        to_account.to_string(),
        token_mint.to_string(),
        associated_account.to_string()
    );
    // s.create_associated_token_account(&to_account, &token_mint)
    //     .await
    //     .unwrap();

    let r = s
        .mint_to(associated_account, amount, token_mint)
        .await
        .unwrap();
    r.to_string()
}

ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    use bincode::Options;
    use serde_json::{from_str, from_value, json, Value};
    use spl_token_2022::instruction::TokenInstruction;
    use spl_token_2022::solana_program::{program_option::COption, pubkey::Pubkey};

    use super::system_instruction::SystemInstruction;
    use ic_solana::rpc_client::JsonRpcResponse;
    use serde::{Deserialize, Serialize};
    // use spl_token_2022::pod_instruction::PodTokenInstruction;

    // #[derive(Debug, Serialize, Deserialize, Clone)]
    // pub struct JsonRpcError {
    //     pub code: i64,
    //     pub message: String,
    // }

    // #[derive(Serialize, Deserialize, Debug)]
    // struct JsonRpcResponse {
    //     jsonrpc: String,
    //     result: TransactionResult,
    //     // error: Option<JsonRpcError>,
    //     id: u64,
    // }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct TransactionResult {
        block_time: Option<u64>,
        meta: Meta,
        slot: u64,
        transaction: Transaction,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Meta {
        compute_units_consumed: u64,
        err: Option<Value>,
        fee: u64,
        inner_instructions: Vec<Value>,
        log_messages: Vec<String>,
        post_balances: Vec<u64>,
        post_token_balances: Vec<Value>,
        pre_balances: Vec<u64>,
        pre_token_balances: Vec<Value>,
        rewards: Vec<Value>,
        status: Status,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct Status {
        #[serde(rename = "Ok")]
        ok: Option<Value>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct Transaction {
        message: Message,
        signatures: Vec<String>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Message {
        account_keys: Vec<AccountKey>,
        instructions: Vec<Instruction>,
        recent_blockhash: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct AccountKey {
        pubkey: String,
        signer: bool,
        source: String,
        writable: bool,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Instruction {
        #[serde(flatten)]
        parsed: Option<Value>,
        program: String,
        program_id: String,
        stack_height: Option<u64>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    // #[serde(untagged)]
    struct ParsedValue {
        parsed: ParsedInstruction,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(untagged)]
    enum ParsedInstruction {
        InstructionEnum(Value),
        Memo(String),
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(untagged)]
    enum InstructionEnum {
        TransferInstruction(ParsedTransfer),
        BurnInstrcution(ParsedBurn),
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct ParsedTransfer {
        info: Transfer,
        #[serde(rename = "type")]
        instr_type: String,
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct Transfer {
        destination: Option<String>,
        lamports: Option<u64>,
        source: Option<String>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct ParsedBurn {
        info: Burn,
        #[serde(rename = "type")]
        instr_type: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Burn {
        account: Option<String>,
        authority: Option<String>,
        mint: Option<String>,
        token_amount: Option<TokenAmount>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct TokenAmount {
        amount: Option<String>,
        decimals: Option<u8>,
        ui_amount: Option<f64>,
        ui_amount_string: Option<String>,
    }

    #[test]
    fn test_parse_transfer_with_memo_tx() {
        let json_data = r#"
        {
            "jsonrpc": "2.0",
            "result": {
                "blockTime": 1721963687,
                "meta": {
                    "computeUnitsConsumed": 7350,
                    "err": null,
                    "fee": 5000,
                    "innerInstructions": [],
                    "logMessages": [
                        "Program 11111111111111111111111111111111 invoke [1]",
                        "Program 11111111111111111111111111111111 success",
                        "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr invoke [1]",
                        "Program log: Memo (len 16): \"receiver_address\"",
                        "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr consumed 7200 of 399850 compute units",
                        "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr success"
                    ],
                    "postBalances": [
                        5999995000,
                        12008970000,
                        1,
                        521498880
                    ],
                    "postTokenBalances": [],
                    "preBalances": [
                        8000000000,
                        10008970000,
                        1,
                        521498880
                    ],
                    "preTokenBalances": [],
                    "rewards": [],
                    "status": {
                        "Ok": null
                    }
                },
                "slot": 314272704,
                "transaction": {
                    "message": {
                        "accountKeys": [
                            {
                                "pubkey": "74SqAGc8wHgkwNx2Hqiz1UdKkZL1gCCvsRRwN2tSm8Ny",
                                "signer": true,
                                "source": "transaction",
                                "writable": true
                            },
                            {
                                "pubkey": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                                "signer": false,
                                "source": "transaction",
                                "writable": true
                            },
                            {
                                "pubkey": "11111111111111111111111111111111",
                                "signer": false,
                                "source": "transaction",
                                "writable": false
                            },
                            {
                                "pubkey": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                                "signer": false,
                                "source": "transaction",
                                "writable": false
                            }
                        ],
                        "instructions": [
                            {
                                "parsed": {
                                    "info": {
                                        "destination": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                                        "lamports": 2000000000,
                                        "source": "74SqAGc8wHgkwNx2Hqiz1UdKkZL1gCCvsRRwN2tSm8Ny"
                                    },
                                    "type": "transfer"
                                },
                                "program": "system",
                                "programId": "11111111111111111111111111111111",
                                "stackHeight": null
                            },
                            {
                                "parsed": "receiver_address",
                                "program": "spl-memo",
                                "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                                "stackHeight": null
                            }
                        ],
                        "recentBlockhash": "BVoPc2NaRNnGBrFssmapBZTycQGyXzxtFn1Uciy52GTT"
                    },
                    "signatures": [
                        "zPTNV4iYR4xdtMupgkFfBYuL99VpdByNGjahNrMjRfWr2FWCRJeMiq3za5pSWT1Jj8z9bG3fBknWfmdL7XFRxud"
                    ]
                }
            },
            "id": 0
        }
        "#;

        let transaction_response =
            serde_json::from_str::<JsonRpcResponse<TransactionResult>>(json_data).unwrap();
        // let transaction_response: JsonRpcResponse = serde_json::from_str(json_data).unwrap();

        println!("transaction_response: {:#?}", transaction_response);
        for instruction in &transaction_response
            .result
            .unwrap()
            .transaction
            .message
            .instructions
        {
            if let Some(parsed_value) = &instruction.parsed {
                if let Ok(parsed_instr) = from_value::<ParsedValue>(parsed_value.clone()) {
                    println!("Parsed Instruction: {:#?}", parsed_instr);
                } else if let Ok(parsed_str) = from_value::<String>(parsed_value.clone()) {
                    println!("Parsed String: {:#?}", parsed_str);
                } else {
                    println!("Unknown Parsed Value: {:#?}", parsed_value);
                }
            }
        }
    }

    #[test]
    fn test_parse_burn_with_memo_tx() {
        let json_data = r#"
        {
    "jsonrpc": "2.0",
    "result": {
        "blockTime": 1722149061,
        "meta": {
            "computeUnitsConsumed": 36589,
            "err": null,
            "fee": 5000,
            "innerInstructions": [],
            "logMessages": [
                "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr invoke [1]",
                "Program log: Signed by 3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                "Program log: Memo (len 44): \"3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia\"",
                "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr consumed 30755 of 400000 compute units",
                "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr success",
                "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb invoke [1]",
                "Program log: Instruction: BurnChecked",
                "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb consumed 5834 of 369245 compute units",
                "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb success"
            ],
            "postBalances": [
                12008965000,
                3883680,
                2074080,
                521498880,
                1141440
            ],
            "postTokenBalances": [
                {
                    "accountIndex": 2,
                    "mint": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                    "owner": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                    "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                    "uiTokenAmount": {
                        "amount": "90000000000",
                        "decimals": 9,
                        "uiAmount": 90.0,
                        "uiAmountString": "90"
                    }
                }
            ],
            "preBalances": [
                12008970000,
                3883680,
                2074080,
                521498880,
                1141440
            ],
            "preTokenBalances": [
                {
                    "accountIndex": 2,
                    "mint": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                    "owner": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                    "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                    "uiTokenAmount": {
                        "amount": "100000000000",
                        "decimals": 9,
                        "uiAmount": 100.0,
                        "uiAmountString": "100"
                    }
                }
            ],
            "rewards": [],
            "status": {
                "Ok": null
            }
        },
        "slot": 314771079,
        "transaction": {
            "message": {
                "accountKeys": [
                    {
                        "pubkey": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                        "signer": true,
                        "source": "transaction",
                        "writable": true
                    },
                    {
                        "pubkey": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                        "signer": false,
                        "source": "transaction",
                        "writable": true
                    },
                    {
                        "pubkey": "D58qMHmDAoEaviG8s9VmGwRhcw2z1apJHt6RnPtgxdVj",
                        "signer": false,
                        "source": "transaction",
                        "writable": true
                    },
                    {
                        "pubkey": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                        "signer": false,
                        "source": "transaction",
                        "writable": false
                    },
                    {
                        "pubkey": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                        "signer": false,
                        "source": "transaction",
                        "writable": false
                    }
                ],
                "instructions": [
                    {
                        "parsed": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                        "program": "spl-memo",
                        "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                        "stackHeight": null
                    },
                    {
                        "parsed": {
                            "info": {
                                "account": "D58qMHmDAoEaviG8s9VmGwRhcw2z1apJHt6RnPtgxdVj",
                                "authority": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                                "mint": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                                "tokenAmount": {
                                    "amount": "10000000000",
                                    "decimals": 9,
                                    "uiAmount": 10.0,
                                    "uiAmountString": "10"
                                }
                            },
                            "type": "burnChecked"
                        },
                        "program": "spl-token",
                        "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                        "stackHeight": null
                    }
                ],
                "recentBlockhash": "HXnTGc3GHrcAuDkAJKyH7wStMii51vYYuMyBGpkAMt61"
            },
            "signatures": [
                "5FHvSDvAmsUnyBRurtsJ3RjMz45CtqUjBP5FvQBQiXBCHfXwb3xqP7cBXGnuDepeGwCR8cE51NJVZY2GHms4GG1Z"
            ]
        }
    },
    "id": 1
}
        "#;

        let transaction_response =
            serde_json::from_str::<JsonRpcResponse<TransactionResult>>(json_data).unwrap();
        // let transaction_response: JsonRpcResponse = serde_json::from_str(json_data).unwrap();

        println!("transaction_response: {:#?}", transaction_response);
        for instruction in &transaction_response
            .result
            .unwrap()
            .transaction
            .message
            .instructions
        {
            if let Some(parsed_value) = &instruction.parsed {
                if let Ok(parsed_instr) = from_value::<ParsedValue>(parsed_value.clone()) {
                    println!("Parsed Instruction: {:#?}", parsed_instr);
                } else if let Ok(parsed_str) = from_value::<String>(parsed_value.clone()) {
                    println!("Parsed String: {:#?}", parsed_str);
                } else {
                    println!("Unknown Parsed Value: {:#?}", parsed_value);
                }
            }
        }
    }

    #[test]
    fn test_parse_transfer_burn_with_memo_tx() {
        let json_data = r#"
    {
"jsonrpc": "2.0",
"result": {
    "blockTime": 1722149061,
    "meta": {
        "computeUnitsConsumed": 36589,
        "err": null,
        "fee": 5000,
        "innerInstructions": [],
        "logMessages": [
            "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr invoke [1]",
            "Program log: Signed by 3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
            "Program log: Memo (len 44): \"3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia\"",
            "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr consumed 30755 of 400000 compute units",
            "Program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr success",
            "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb invoke [1]",
            "Program log: Instruction: BurnChecked",
            "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb consumed 5834 of 369245 compute units",
            "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb success"
        ],
        "postBalances": [
            12008965000,
            3883680,
            2074080,
            521498880,
            1141440
        ],
        "postTokenBalances": [
            {
                "accountIndex": 2,
                "mint": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                "owner": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                "uiTokenAmount": {
                    "amount": "90000000000",
                    "decimals": 9,
                    "uiAmount": 90.0,
                    "uiAmountString": "90"
                }
            }
        ],
        "preBalances": [
            12008970000,
            3883680,
            2074080,
            521498880,
            1141440
        ],
        "preTokenBalances": [
            {
                "accountIndex": 2,
                "mint": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                "owner": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                "uiTokenAmount": {
                    "amount": "100000000000",
                    "decimals": 9,
                    "uiAmount": 100.0,
                    "uiAmountString": "100"
                }
            }
        ],
        "rewards": [],
        "status": {
            "Ok": null
        }
    },
    "slot": 314771079,
    "transaction": {
        "message": {
            "accountKeys": [
                {
                    "pubkey": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                    "signer": true,
                    "source": "transaction",
                    "writable": true
                },
                {
                    "pubkey": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                    "signer": false,
                    "source": "transaction",
                    "writable": true
                },
                {
                    "pubkey": "D58qMHmDAoEaviG8s9VmGwRhcw2z1apJHt6RnPtgxdVj",
                    "signer": false,
                    "source": "transaction",
                    "writable": true
                },
                {
                    "pubkey": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                    "signer": false,
                    "source": "transaction",
                    "writable": false
                },
                {
                    "pubkey": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                    "signer": false,
                    "source": "transaction",
                    "writable": false
                }
            ],
            "instructions": [
                {
                    "parsed": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                    "program": "spl-memo",
                    "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                    "stackHeight": null
                },
                {
                    "parsed": {
                        "info": {
                            "account": "D58qMHmDAoEaviG8s9VmGwRhcw2z1apJHt6RnPtgxdVj",
                            "authority": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                            "mint": "AN2n5RYpqH9FfgD5zHFZS2wkezPTAhrukbPYvbx4ZEAj",
                            "tokenAmount": {
                                "amount": "10000000000",
                                "decimals": 9,
                                "uiAmount": 10.0,
                                "uiAmountString": "10"
                            }
                        },
                        "type": "burnChecked"
                    },
                    "program": "spl-token",
                    "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                    "stackHeight": null
                },
                {
                                "parsed": {
                                    "info": {
                                        "destination": "3gghk7mHWtFsJcg6EZGK7sbHj3qW6ExUdZLs9q8GRjia",
                                        "lamports": 2000000000,
                                        "source": "74SqAGc8wHgkwNx2Hqiz1UdKkZL1gCCvsRRwN2tSm8Ny"
                                    },
                                    "type": "transfer"
                                },
                                "program": "system",
                                "programId": "11111111111111111111111111111111",
                                "stackHeight": null
                            }
            ],
            "recentBlockhash": "HXnTGc3GHrcAuDkAJKyH7wStMii51vYYuMyBGpkAMt61"
        },
        "signatures": [
            "5FHvSDvAmsUnyBRurtsJ3RjMz45CtqUjBP5FvQBQiXBCHfXwb3xqP7cBXGnuDepeGwCR8cE51NJVZY2GHms4GG1Z"
        ]
    }
},
"id": 1
}
    "#;

        let transaction_response =
            serde_json::from_str::<JsonRpcResponse<TransactionResult>>(json_data).unwrap();
        // let transaction_response: JsonRpcResponse = serde_json::from_str(json_data).unwrap();

        println!("transaction_response: {:#?}", transaction_response);
        for instruction in &transaction_response
            .result
            .unwrap()
            .transaction
            .message
            .instructions
        {
            if let Some(parsed_value) = &instruction.parsed {
                if let Ok(parsed_instr) = from_value::<ParsedValue>(parsed_value.clone()) {
                    println!("Parsed Instruction: {:#?}", parsed_instr);
                } else if let Ok(parsed_str) = from_value::<String>(parsed_value.clone()) {
                    println!("Parsed String: {:#?}", parsed_str);
                } else {
                    println!("Unknown Parsed Value: {:#?}", parsed_value);
                }
            }
        }
    }

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
