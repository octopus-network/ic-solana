use crate::compute_budget::compute_budget::{
    ComputeBudgetInstruction, Priority, DEFAULT_COMPUTE_UNITS,
};
// use crate::constants::DELAY;
// use std::time::Duration;
use crate::eddsa::{eddsa_public_key, sign_with_eddsa, KeyType};

use crate::rpc_client::RpcResult;

use crate::token::constants::token22_program_id;

use crate::ic_log::DEBUG;
use crate::metaplex::create_metadata_ix::CreateMetadataArgs;
use crate::metaplex::types::FungibleFields;
use crate::token::token_metadata::{OptionalNonZeroPubkey, TokenMetadata};

use crate::types::{BlockHash, Instruction, Message, Pubkey, Signature, Transaction};
use anyhow::anyhow;

use candid::{CandidType, Principal};
use ic_canister_log::log;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use core::fmt;
use std::str::FromStr;
use token_metadata::Field;
pub mod associated_account;

pub mod constants;
pub mod instruction_error;
pub mod program_error;
pub mod system_instruction;
pub mod token_instruction;
pub mod token_metadata;
use crate::eddsa::hash_with_sha256;
use crate::metaplex::create_fungible22_ix::create_fungible_22_ix;
use crate::metaplex::create_fungible22_ix::CreateFungible22Args;
use crate::metaplex::create_fungible22_ix::Fungible22Fields;
use crate::metaplex::create_fungible22_ix::MetadataConfig;
use crate::metaplex::create_fungible_ix::create_fungible_ix;
use crate::metaplex::create_fungible_ix::CreateFungibleArgs;
use crate::metaplex::create_metadata_ix::create_metadata_ix;
use crate::metaplex::update_metadata_ix::update_asset_v1_ix;
use crate::metaplex::update_metadata_ix::UpdateMetaArgs;
use crate::token::token_instruction::initialize_metadata_pointer;
use anyhow::Error;
use ic_cdk::api;
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub struct TxError {
    pub block_hash: String,
    pub signature: String,
    pub error: String,
}
impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TxError: block_hash={}, signature={}, error={}",
            self.block_hash, self.signature, self.error
        )
    }
}
impl std::error::Error for TxError {}
impl TryFrom<Error> for TxError {
    type Error = Error;

    fn try_from(e: Error) -> Result<Self, Self::Error> {
        if let Some(tx_error) = e.downcast_ref::<TxError>() {
            Ok(TxError {
                block_hash: tx_error.block_hash.to_owned(),
                signature: tx_error.signature.to_owned(),
                error: tx_error.error.to_owned(),
            })
        } else {
            Err(e)
        }
    }
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub uri: String,
}
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SolanaClient {
    pub sol_canister_id: Principal,
    pub payer: Pubkey,
    pub payer_derive_path: Vec<ByteBuf>,
    pub chainkey_name: String,
    pub forward: Option<String>,
    pub priority: Option<Priority>,
    pub key_type: KeyType,
}

impl SolanaClient {
    pub async fn derive_account(
        key_type: KeyType,
        chainkey_name: String,
        derive_path: String,
    ) -> Pubkey {
        let path = vec![ByteBuf::from(derive_path.as_str())];
        Pubkey::try_from(eddsa_public_key(key_type, chainkey_name, path).await).unwrap()
    }

    pub async fn query_transaction(
        &self,
        txhash: String,
        forward: Option<String>,
    ) -> anyhow::Result<String> {
        let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getTransaction",
            (txhash, forward),
        )
        .await;
        let tx = response
            .map_err(|e| anyhow!(format!("query transaction err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("query transaction rpc error: {:?}", e)))?;
        // let tx = serde_json::from_str(tx.as_str()).unwrap();
        Ok(tx)
    }

    pub async fn get_latest_blockhash(&self) -> anyhow::Result<BlockHash> {
        let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_latestBlockhash",
            (self.forward.to_owned(),),
        )
        .await;
        let hash = response
            .map_err(|e| anyhow!(format!("request solana provider error: {:?}, {}", e.0, e.1)))?
            .0
            .map_err(|e| anyhow!(format!("request latest block hash error: {:?}", e)))?;
        Ok(BlockHash::from_str(&hash)?)
    }

    pub async fn get_account_info(
        &self,
        account: String,
        // forward: Option<String>,
    ) -> anyhow::Result<Option<String>> {
        let r: Result<(RpcResult<Option<String>>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getAccountInfo",
            (account, self.forward.to_owned()),
        )
        .await;
        let resp = r
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::get_account_info] call sol_getAccountInfo error: {:?}",
                    e
                ))
            })?
            .0
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::get_account_info] sol_getAccountInfo rpc error:{:?}",
                    e
                ))
            })?;
        log!(
            DEBUG,
            "[solana_client::get_account_info] sol_getAccountInfo resp: {:#?} ",
            resp
        );

        Ok(resp)
    }

    pub async fn get_balance(&self, account: String) -> anyhow::Result<u64> {
        let r: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getBalance",
            (account, self.forward.to_owned()),
        )
        .await;
        let resp = r
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::get_balance] call get_balance error: {:?}",
                    e
                ))
            })?
            .0
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::get_balance] get_balance rpc error:{:?}",
                    e
                ))
            })?;
        log!(
            DEBUG,
            "[solana_client::get_balance] get_balance resp: {:#?} ",
            resp
        );

        Ok(resp)
    }

    pub async fn test_create_mint_with_metaplex(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
        blockhash: BlockHash,
    ) -> anyhow::Result<String> {
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
            payer: self.payer.to_owned(),
        };
        let instructions = vec![create_fungible_ix(create_arg)];
        let derive_path = hash_with_sha256(token_info.token_id.clone().as_str());

        // let blockhash = self.get_latest_blockhash().await?;

        let message = Message::new_with_blockhash(
            instructions.iter().as_ref(),
            Some(&self.payer),
            &blockhash,
        );
        let mut tx = Transaction::new_unsigned(message);
        let paths = vec![
            self.payer_derive_path.clone(),
            vec![ByteBuf::from(derive_path)],
        ];
        let mut start = api::time();
        for i in 0..paths.len() {
            let signature = self
                .sign(&KeyType::ChainKey, paths[i].clone(), tx.message_data())
                .await?;
            tx.add_signature(i, signature);
        }
        let mut end = api::time();
        let mut elapsed = (end - start) / 1_000_000_000;
        log!(
            DEBUG,
            "[solana_client::test_create_mint_with_metaplex] the time elapsed for chainkey signing : {}",
            elapsed
        );

        start = api::time();
        let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_sendRawTransaction",
            (tx.to_string(), self.forward.to_owned()),
        )
        .await;
        log!(DEBUG, "sol_sendRawTransaction response: {:?}", response);
        end = api::time();
        elapsed = (end - start) / 1_000_000_000;
        log!(
            DEBUG,
            "[solana_client::test_create_mint_with_metaplex] the time elapsed for sol_sendRawTransaction : {}",
            elapsed
        );

        let resp = response
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::send_raw_transaction] call send raw transaction err: {:?}",
                    e
                ))
            })?
            .0
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::send_raw_transaction] rpc error: {:?}",
                    e
                ))
            })?;
        // log!(DEBUG, "sol_sendRawTransaction response: {}", resp);

        Ok(resp)
    }

    pub async fn create_mint_with_metaplex(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
    ) -> anyhow::Result<String> {
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
            payer: self.payer.to_owned(),
        };
        let mut instructions = vec![create_fungible_ix(create_arg)];

        let derive_path = hash_with_sha256(token_info.token_id.to_owned().as_str());

        if let Some(priority) = &self.priority {
            self.set_compute_unit(
                &mut instructions,
                vec![
                    self.payer_derive_path.to_owned(),
                    vec![ByteBuf::from(derive_path.to_owned())],
                ],
                priority.to_owned(),
                self.key_type.to_owned(),
            )
            .await?;
        }

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![
                    self.payer_derive_path.to_owned(),
                    vec![ByteBuf::from(derive_path)],
                ],
                self.key_type.to_owned(),
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_mint22_with_metaplex(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let mint_len = 270u64;
        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey(self.payer.clone()),
            mint: token_mint,
            name: token_info.name.clone(),
            symbol: token_info.symbol.clone(),
            uri: token_info.uri.clone(),
            additional_metadata: vec![],
        };
        log!(
            DEBUG,
            "[solana_client::create_mint_with_metadata] metadata: {:#?} ",
            metadata
        );

        let space = metadata.tlv_size_of().unwrap() + mint_len as usize;
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getminimumbalanceforrentexemption",
            (space, self.forward.to_owned()),
        )
        .await;
        let rent_exemption = response
            .map_err(|e| anyhow!(format!("query rent err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("query rent rpc error: {:?}", e)))?;

        let metadata_cfg = MetadataConfig {
            name: token_info.name.to_owned(),
            symbol: token_info.symbol.to_owned(),
            uri: token_info.uri.to_owned(),
            additional_metadata: None,
        };
        let extensions = Fungible22Fields {
            metadata: Some(metadata_cfg),
            close_authority: Some(self.payer.to_string()),
            permanent_delegate: None,
            non_transferrable: None,
            transfer_fee: None,
            interest_bearing: None,
            transfer_hook: None,
        };
        let creat_args = CreateFungible22Args {
            mint: token_mint,
            mint_size: mint_len,
            mint_rent: rent_exemption,
            decimals: token_info.decimals,
            extensions,
            payer: self.payer,
        };

        let instructions = create_fungible_22_ix(creat_args);

        let derive_path = hash_with_sha256(token_info.token_id.clone().as_str());
        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![
                    self.payer_derive_path.clone(),
                    vec![ByteBuf::from(derive_path)],
                ],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_metadata_account(
        &self,
        mint: String,
        metadata: FungibleFields,
        immutable: bool,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let meta_args = CreateMetadataArgs {
            mint: mint,
            metadata: metadata,
            immutable: immutable,
            payer: self.payer.to_owned(),
        };
        let create_ix = create_metadata_ix(meta_args).unwrap();
        let instructions = vec![create_ix];

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn update_with_metaplex(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
    ) -> anyhow::Result<String> {
        let update_meta_args = UpdateMetaArgs {
            payer: self.payer,
            mint_account: token_mint,
            name: token_info.name.to_owned(),
            symbol: token_info.symbol.to_owned(),
            uri: token_info.uri.to_owned(),
            seller_fee_basis_points: 0u16,
            creators: None,
        };
        let mut instructions = vec![update_asset_v1_ix(update_meta_args)];

        if let Some(priority) = &self.priority {
            self.set_compute_unit(
                &mut instructions,
                vec![self.payer_derive_path.to_owned()],
                priority.to_owned(),
                self.key_type.to_owned(),
            )
            .await?;
        }

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.to_owned()],
                self.key_type.to_owned(),
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_mint22(&self, token_create_info: TokenInfo) -> anyhow::Result<Pubkey> {
        let space: usize = 82;
        // get rent exemption
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getminimumbalanceforrentexemption",
            (space, self.forward.to_owned()),
        )
        .await;
        let rent_exemption = response.unwrap().0.unwrap();
        let token_pubkey_derived_path = vec![ByteBuf::from(token_create_info.token_id.as_str())];
        let token_mint = Pubkey::try_from(
            eddsa_public_key(
                crate::eddsa::KeyType::ChainKey,
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
        instructions.push(token_instruction::initialize_mint(
            &token22_program_id(),
            &token_mint,
            &self.payer,
            None,
            token_create_info.decimals,
        ));
        let _tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone(), token_pubkey_derived_path],
                KeyType::ChainKey,
            )
            .await?;
        Ok(token_mint)
    }

    pub async fn create_mint22_with_metadata(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
    ) -> anyhow::Result<String> {
        let mint_len = 234u64;
        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey(self.payer.clone()),
            mint: token_mint,
            name: token_info.name.clone(),
            symbol: token_info.symbol.clone(),
            uri: token_info.uri.clone(),
            additional_metadata: vec![],
        };
        log!(
            DEBUG,
            "[solana_client::create_mint_with_metadata] metadata: {:#?} ",
            metadata
        );

        let space = metadata.tlv_size_of().unwrap() + 238;
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getminimumbalanceforrentexemption",
            (space, self.forward.to_owned()),
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
        instructions.push(initialize_metadata_pointer(
            &token_mint,
            &token_mint,
            &self.payer,
        ));
        instructions.push(token_instruction::initialize_mint(
            &token22_program_id(),
            &token_mint,
            &self.payer,
            Some(&self.payer),
            token_info.decimals,
        ));
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

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![
                    self.payer_derive_path.clone(),
                    vec![ByteBuf::from(token_info.token_id.clone())],
                ],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_associated_token_account(
        &self,
        owner_addr: &Pubkey,
        token_mint: &Pubkey,
        token_program_id: &Pubkey,
    ) -> anyhow::Result<String> {
        let mut instructions = vec![
            crate::token::associated_account::create_associated_token_account(
                &self.payer,
                &owner_addr,
                &token_mint,
                &token_program_id,
            ),
        ];

        if let Some(priority) = &self.priority {
            self.set_compute_unit(
                &mut instructions,
                vec![self.payer_derive_path.to_owned()],
                priority.to_owned(),
                self.key_type.to_owned(),
            )
            .await?;
        }

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.to_owned()],
                self.key_type.to_owned(),
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn mint_to(
        &self,
        associated_account: Pubkey,
        amount: u64,
        token_mint: Pubkey,
        token_program_id: Pubkey,
    ) -> anyhow::Result<String> {
        let mut instructions = vec![token_instruction::mint_to(
            &token_program_id,
            &token_mint,
            &associated_account,
            &self.payer,
            &[],
            amount,
        )];

        if let Some(priority) = &self.priority {
            self.set_compute_unit(
                &mut instructions,
                vec![self.payer_derive_path.to_owned()],
                priority.to_owned(),
                self.key_type.to_owned(),
            )
            .await?;
        }

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.to_owned()],
                self.key_type.to_owned(),
            )
            .await?;

        Ok(tx_hash)
    }

    pub async fn update_token22_metadata(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
    ) -> anyhow::Result<String> {
        let mint_len = 270u64;
        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey(self.payer.to_owned()),
            mint: token_mint,
            name: token_info.name.clone(),
            symbol: token_info.symbol.clone(),
            uri: token_info.uri.clone(),
            additional_metadata: vec![],
        };
        let space = metadata.tlv_size_of().unwrap() + mint_len as usize;
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getminimumbalanceforrentexemption",
            (space, self.forward.to_owned()),
        )
        .await;
        let rent_exemption = response
            .map_err(|e| anyhow!(format!("query rent err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("query rent rpc error: {:?}", e)))?;
        let mut instructions = vec![system_instruction::transfer(
            &self.payer,
            &token_mint,
            rent_exemption,
        )];
        instructions.push(token_metadata::update_field(
            &token22_program_id(),
            &token_mint,
            &self.payer,
            Field::Name,
            token_info.name.clone(),
        ));

        instructions.push(token_metadata::update_field(
            &token22_program_id(),
            &token_mint,
            &self.payer,
            Field::Symbol,
            token_info.symbol.clone(),
        ));

        instructions.push(token_metadata::update_field(
            &token22_program_id(),
            &token_mint,
            &self.payer,
            Field::Uri,
            token_info.uri.clone(),
        ));

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn transfer_to(&self, to_account: Pubkey, amount: u64) -> anyhow::Result<String> {
        let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getBalance",
            (to_account.to_string(), self.forward.to_owned()),
        )
        .await;

        let lamports = response
            .map_err(|e| anyhow!(format!("sol_getBalance err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("sol_getBalance rpc error: {:?}", e)))?;

        let fee = 10_000;

        if lamports <= amount + fee {
            ic_cdk::trap("Not enough lamports");
        }

        let instructions = vec![system_instruction::transfer(
            &self.payer,
            &to_account,
            amount,
        )];

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }

    async fn sign(
        &self,
        key_type: &KeyType,
        key_path: Vec<ByteBuf>,
        tx: Vec<u8>,
    ) -> anyhow::Result<Signature> {
        let signature = sign_with_eddsa(key_type, self.chainkey_name.clone(), key_path, tx)
            .await
            .try_into()
            .map_err(|e| anyhow!("invalid signature: {:?}", e))?;
        Ok(signature)
    }

    async fn send_raw_transaction(
        &self,
        instructions: &[Instruction],
        paths: Vec<Vec<ByteBuf>>,
        key_type: KeyType,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let mut start = api::time();
        let blockhash = self.get_latest_blockhash().await?;
        let mut end = api::time();
        let mut elapsed = (end - start) / 1_000_000_000;

        log!(
            DEBUG,
            "[solana_client::send_raw_transaction] get_latest_blockhash : {:?} and time elapsed: {}",
            blockhash,elapsed
        );

        let message = Message::new_with_blockhash(
            instructions.iter().as_ref(),
            Some(&self.payer),
            &blockhash.to_owned(),
        );
        let mut tx = Transaction::new_unsigned(message);
        // let mut tx_hash = String::new();
        start = api::time();
        for i in 0..paths.len() {
            let signature = self
                .sign(&key_type, paths[i].clone(), tx.message_data())
                .await?;
            tx.add_signature(i, signature);
        }
        end = api::time();
        elapsed = (end - start) / 1_000_000_000;

        log!(
            DEBUG,
            "[solana_client::send_raw_transaction] the time elapsed for chainkey signing : {}",
            elapsed
        );
        let tx_hash = tx.signatures.first().unwrap().to_string();
        log!(
            DEBUG,
            "[solana_client::send_raw_transaction] tx first signature : {}",
            tx_hash
        );

        start = api::time();
        let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_sendRawTransaction",
            (tx.to_string(), self.forward.to_owned()),
        )
        .await;
        log!(DEBUG, "sol_sendRawTransaction response: {:?}", response);
        end = api::time();
        elapsed = (end - start) / 1_000_000_000;
        log!(
            DEBUG,
            "[solana_client::send_raw_transaction] the time elapsed for sol_sendRawTransaction : {}",
            elapsed
        );

        let resp = response
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::send_raw_transaction] call send raw transaction err: {:?}",
                    e
                ))
            })?
            .0
            .map_err(|e| {
                let tx_error = TxError {
                    block_hash: blockhash.to_string(),
                    signature: tx_hash,
                    error: format!("[solana_client::send_raw_transaction] rpc error: {:?}", e),
                };
                anyhow!(tx_error)
            })?;

        Ok(resp)
    }

    pub async fn get_compute_units(
        &self,
        instructions: &[Instruction],
        paths: Vec<Vec<ByteBuf>>,
        key_type: KeyType,
    ) -> anyhow::Result<Option<u64>> {
        let message = Message::new(instructions.iter().as_ref(), Some(&self.payer));
        let mut tx = Transaction::new_unsigned(message);

        for i in 0..paths.len() {
            let signature = self
                .sign(&key_type, paths[i].clone(), tx.message_data())
                .await?;
            tx.add_signature(i, signature);
        }

        let response: Result<(RpcResult<Option<u64>>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getComputeUnits",
            (tx.to_string(), self.forward.to_owned()),
        )
        .await;

        log!(DEBUG, "sol_getComputeUnits response: {:?}", response);

        let resp = response
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::get_compute_units] call sol_getComputeUnits err: {:?}",
                    e
                ))
            })?
            .0
            .map_err(|e| {
                anyhow!(format!(
                    "[solana_client::get_compute_units] rpc error: {:?}",
                    e
                ))
            })?;

        log!(DEBUG, "get_compute_units response: {:?}", resp);

        Ok(resp)
    }

    async fn set_compute_unit(
        &self,
        instructions: &mut Vec<Instruction>,
        paths: Vec<Vec<ByteBuf>>,
        priority: Priority,
        key_type: KeyType,
    ) -> Result<(), anyhow::Error> {
        let micro_lamports = match priority {
            Priority::None => 20,        // 1       lamports
            Priority::Low => 20_000,     // 1_000   lamports  ~$1 for 10k updates
            Priority::Medium => 200_000, // 10_000  lamports  ~$10 for 10k updates
            Priority::High => 1_000_000, // 50_000  lamports  ~$0.01/update @ $150 SOL
            Priority::Max => 2_000_000,  // 100_000 lamports  ~$0.02/update @ $150 SOL
        };
        let mut extra_instructions = vec![];
        let compute_units = self
            .get_compute_units(&*instructions, paths, key_type)
            .await?
            .unwrap_or(DEFAULT_COMPUTE_UNITS);
        extra_instructions.push(ComputeBudgetInstruction::set_compute_unit_limit(
            compute_units as u32,
        ));
        extra_instructions.push(ComputeBudgetInstruction::set_compute_unit_price(
            micro_lamports,
        ));
        instructions.splice(0..0, extra_instructions);

        Ok(())
    }

    pub async fn close_account(
        &self,
        token_program_id: Pubkey,
        close_account: Pubkey,
        dest_account: Pubkey,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let instructions = vec![token_instruction::close_account(
            &token_program_id,
            &close_account,
            &dest_account,
            &self.payer,
            &[],
        )];
        log!(
            DEBUG,
            "[solana_client::close_account] instructions: {:?} ",
            instructions
        );

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn freeze_account(
        &self,
        token_program_id: Pubkey,
        freeze_account: Pubkey,
        mint_account: Pubkey,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let instructions = vec![token_instruction::freeze_account(
            &token_program_id,
            &freeze_account,
            &mint_account,
            &self.payer,
            &[],
        )];
        log!(
            DEBUG,
            "[solana_client::freeze_account] instructions: {:?} ",
            instructions
        );

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
                KeyType::ChainKey,
            )
            .await?;
        Ok(tx_hash)
    }
}
