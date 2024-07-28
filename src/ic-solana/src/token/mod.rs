use crate::eddsa::{eddsa_public_key, sign_with_eddsa};
use crate::rpc_client::RpcResult;
use crate::token::associated_account::get_associated_token_address_with_program_id;
use crate::token::constants::token22_program_id;
use crate::token::token_metadata::{OptionalNonZeroPubkey, TokenMetadata};
use crate::types::{
    Account, AccountMeta, BlockHash, EncodedConfirmedTransactionWithStatusMeta, Instruction,
    Message, Pubkey, Signature, Transaction,
};
use anyhow::anyhow;
use candid::Principal;
use serde_bytes::ByteBuf;
use std::str::FromStr;

pub mod associated_account;
pub mod constants;
pub mod instruction_error;
pub mod program_error;
pub mod system_instruction;
pub mod token_instruction;
pub mod token_metadata;

pub struct TokenCreateInfo {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub uri: String,
}

pub struct SolanaClient {
    pub sol_canister_id: Principal,
    pub payer: Pubkey,
    pub payer_derive_path: Vec<ByteBuf>,
    pub chainkey_name: String,
    pub schnorr_canister: Principal,
}

impl SolanaClient {
    pub async fn derive_account(
        schnorr_canister: Principal,
        chainkey_name: String,
        derive_path: String,
    ) -> Pubkey {
        let path = vec![ByteBuf::from(derive_path.as_str())];
        Pubkey::try_from(eddsa_public_key(schnorr_canister, chainkey_name, path).await).unwrap()
    }

    pub async fn query_transaction(
        &self,
        txhash: String,
    ) -> anyhow::Result<EncodedConfirmedTransactionWithStatusMeta> {
        let transaction: Result<(RpcResult<EncodedConfirmedTransactionWithStatusMeta>,), _> =
            ic_cdk::call(
                self.sol_canister_id,
                "sol_getTransaction",
                (txhash.to_string(),),
            )
            .await;
        ic_cdk::println!("sol_getTransaction response: {:#?}", transaction);

        // let response: Result<RpcResult<EncodedConfirmedTransactionWithStatusMeta>, _> =
        //     ic_cdk::call(self.sol_canister_id, "sol_getTransaction", (txhash,)).await;
        let tx = transaction
            .map_err(|e| anyhow!(format!("call sol_getTransaction err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("sol_getTransaction rpc error: {:?}", e)))?;
        Ok(tx)
    }

    // parse the redeem transaction via signatrure,return (transition fee info (sender,receiver and amount) ,burned info (account and amount),receiver include memo)
    //
    pub async fn parse_redeem_transaction(
        &self,
        signature: String,
    ) -> anyhow::Result<EncodedConfirmedTransactionWithStatusMeta> {
        let response: Result<(RpcResult<String>,), _> =
            ic_cdk::call(self.sol_canister_id, "sol_getTransaction", (txhash,)).await;
        let tx = response
            .map_err(|e| anyhow!(format!("call sol_getTransaction err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("sol_getTransaction rpc error: {:?}", e)))?;
        Ok(tx)
    }

    pub async fn get_latest_blockhash(&self) -> anyhow::Result<BlockHash> {
        let response: Result<(RpcResult<String>,), _> =
            ic_cdk::call(self.sol_canister_id, "sol_latestBlockhash", ()).await;
        let hash = response
            .map_err(|e| anyhow!(format!("request solana provider error: {:?}, {}", e.0, e.1)))?
            .0
            .map_err(|e| anyhow!(format!("request latest block hash error: {:?}", e)))?;
        Ok(BlockHash::from_str(&hash)?)
    }

    pub async fn mint_to(
        &self,
        to_account: Pubkey,
        amount: u64,
        token_mint: Pubkey,
    ) -> anyhow::Result<String> {
        let associated_token_account = self.associated_account(&to_account, &token_mint).await?;
        let instructions = vec![token_instruction::mint_to(
            &token22_program_id(),
            &token_mint,
            &associated_token_account,
            &self.payer,
            &[],
            amount,
        )
        .unwrap()];
        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_mint(&self, token_create_info: TokenCreateInfo) -> anyhow::Result<Pubkey> {
        let space: usize = 82;
        // get rent exemption
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getminimumbalanceforrentexemption",
            (space,),
        )
        .await;
        let rent_exemption = response.unwrap().0.unwrap();
        let token_pubkey_derived_path = vec![ByteBuf::from(token_create_info.name.as_str())];
        let token_mint = Pubkey::try_from(
            eddsa_public_key(
                self.schnorr_canister,
                self.chainkey_name.clone(),
                token_pubkey_derived_path.clone(),
            )
            .await,
        )
        .unwrap();
        let mut instructions = vec![system_instruction::create_account(
            &self.payer,
            &token_mint,
            rent_exemption,
            space as u64,
            &token22_program_id(),
        )];
        instructions.push(
            token_instruction::initialize_mint(
                &token22_program_id(),
                &token_mint,
                &self.payer,
                None,
                token_create_info.decimals,
            )
            .unwrap(),
        );
        let _tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone(), token_pubkey_derived_path],
            )
            .await?;
        Ok(token_mint)
    }

    pub async fn associated_account(
        &self,
        owner: &Pubkey,
        token_mint: &Pubkey,
    ) -> anyhow::Result<Pubkey> {
        let associated_account =
            get_associated_token_address_with_program_id(owner, token_mint, &token22_program_id());
        let r: Result<(RpcResult<Option<Account>>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getAccountInfo",
            (associated_account.to_string(),),
        )
        .await;
        let resp = r
            .map_err(|e| anyhow!(format!("query account info error: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("query account info rpc error:{:?}", e)))?;
        match resp {
            None => {
                //create_account
                self.create_associated_token_account(owner, token_mint)
                    .await?;
                Ok(associated_account)
            }
            //TODO: confime if create_associated_token_account?
            Some(_) => Ok(associated_account),
        }
    }

    async fn create_associated_token_account(
        &self,
        owner_addr: &Pubkey,
        token_mint: &Pubkey,
    ) -> anyhow::Result<()> {
        let instructions = vec![
            crate::token::associated_account::create_associated_token_account(
                &self.payer,
                &owner_addr,
                &token_mint,
                &token22_program_id(),
            ),
        ];
        let _tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
            )
            .await?;
        Ok(())
    }

    pub async fn create_mint_with_metadata(
        &self,
        token_info: TokenCreateInfo,
    ) -> anyhow::Result<Pubkey> {
        let token_mint = Self::derive_account(
            self.schnorr_canister.clone(),
            self.chainkey_name.clone(),
            token_info.name.clone(),
        )
        .await;
        let mint_len = 234u64;
        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey(self.payer.clone()),
            mint: token_mint,
            name: token_info.name.clone(),
            symbol: token_info.symbol.clone(),
            uri: token_info.uri.clone(),
            additional_metadata: vec![],
        };
        let space = metadata.tlv_size_of().unwrap() + 238;
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getminimumbalanceforrentexemption",
            (space,),
        )
        .await;
        let rent_exemption = response
            .map_err(|e| anyhow!(format!("query rent err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("query rent rpc error: {:?}", e)))?;
        let mut instructions = vec![system_instruction::create_account(
            &self.payer,
            &token_mint,
            rent_exemption,
            mint_len,
            &token22_program_id(),
        )];
        instructions.push(Self::generate_metadata_pointer_instruction(
            &token_mint,
            &token_mint,
            &self.payer,
        ));
        instructions.push(
            token_instruction::initialize_mint(
                &token22_program_id(),
                &token_mint,
                &self.payer,
                Some(&self.payer),
                token_info.decimals,
            )
            .unwrap(),
        );
        instructions.push(token_metadata::initialize(
            &token22_program_id(),
            &token_mint,
            &self.payer,
            &token_mint,
            &self.payer,
            token_info.name.clone(),
            token_info.symbol,
            token_info.uri,
        ));

        let _tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![
                    self.payer_derive_path.clone(),
                    vec![ByteBuf::from(token_info.name.clone())],
                ],
            )
            .await?;
        Ok(token_mint)
    }

    fn generate_metadata_pointer_instruction(
        token_mint: &Pubkey,
        metadata_addr: &Pubkey,
        authority: &Pubkey,
    ) -> Instruction {
        let mut data: Vec<u8> = Vec::new();
        data.push(39u8);
        data.push(0u8);
        data.extend_from_slice(authority.0.as_slice());
        data.extend_from_slice(metadata_addr.0.as_slice());
        let accounts = vec![AccountMeta::new(*token_mint, false)];
        Instruction {
            program_id: token22_program_id(),
            accounts,
            data,
        }
    }

    async fn sign(&self, key_path: Vec<ByteBuf>, tx: Vec<u8>) -> anyhow::Result<Signature> {
        let signature = sign_with_eddsa(
            self.schnorr_canister,
            self.chainkey_name.clone(),
            key_path,
            tx,
        )
        .await
        .try_into()
        .map_err(|e| anyhow!("invalid signature :{:?}", e))?;
        Ok(signature)
    }

    async fn send_raw_transaction(
        &self,
        instructions: &[Instruction],
        paths: Vec<Vec<ByteBuf>>,
    ) -> anyhow::Result<String> {
        let blockhash = self.get_latest_blockhash().await?;
        let message = Message::new_with_blockhash(
            instructions.iter().as_ref(),
            Some(&self.payer),
            &blockhash,
        );
        let mut tx = Transaction::new_unsigned(message);
        for i in 0..paths.len() {
            let signature = self.sign(paths[i].clone(), tx.message_data()).await?;
            tx.add_signature(i, signature);
        }
        let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_sendRawTransaction",
            (tx.to_string(),),
        )
        .await;
        let signature = response
            .map_err(|e| anyhow!(format!("send raw transaction err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("send raw transaction rpc error: {:?}", e)))?;
        ic_cdk::println!("{}", signature);
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::{from_value, Value};

    use crate::rpc_client::JsonRpcResponse;
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
}
