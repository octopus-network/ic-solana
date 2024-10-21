use crate::eddsa::{eddsa_public_key, sign_with_eddsa};

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

use std::str::FromStr;
use token_metadata::Field;
pub mod associated_account;
pub mod compute_budget;
pub mod constants;
pub mod instruction_error;
pub mod program_error;
pub mod system_instruction;
pub mod token_instruction;
pub mod token_metadata;
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
}

impl SolanaClient {
    pub async fn derive_account(chainkey_name: String, derive_path: String) -> Pubkey {
        let path = vec![ByteBuf::from(derive_path.as_str())];
        Pubkey::try_from(eddsa_public_key(chainkey_name, path).await).unwrap()
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

    pub async fn create_mint_with_metaplex(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
        // forward: Option<String>,
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
        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![
                    self.payer_derive_path.clone(),
                    vec![ByteBuf::from(token_info.token_id.clone())],
                ],
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

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![
                    self.payer_derive_path.clone(),
                    vec![ByteBuf::from(token_info.token_id.clone())],
                ],
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
        // let space: usize = 82;
        // get rent exemption
        // let response: Result<(RpcResult<u64>,), _> = ic_cdk::call(
        //     self.sol_canister_id,
        //     "sol_getminimumbalanceforrentexemption",
        //     (space, self.forward.to_owned()),
        // )
        // .await;
        // let rent_exemption = response.unwrap().0.unwrap();

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
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn update_with_metaplex(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
        // forward: Option<String>,
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
        let instructions = vec![update_asset_v1_ix(update_meta_args)];
        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.to_owned()],
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_mint22(
        &self,
        token_create_info: TokenInfo,
        // forward: Option<String>,
    ) -> anyhow::Result<Pubkey> {
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
            )
            .await?;
        Ok(token_mint)
    }

    pub async fn create_mint22_with_metadata(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
        // forward: Option<String>,
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

        // log!(
        //     DEBUG,
        //     "[solana_client::create_mint_with_metadata] payer: {:?} ",
        //     self.payer.to_string()
        // );

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
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn create_associated_token_account(
        &self,
        owner_addr: &Pubkey,
        token_mint: &Pubkey,
        token_program_id: &Pubkey, // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let instructions = vec![
            crate::token::associated_account::create_associated_token_account(
                &self.payer,
                &owner_addr,
                &token_mint,
                &token_program_id,
            ),
        ];
        log!(
            DEBUG,
            "[solana_client::create_associated_token_account] instructions :{:?} ",
            instructions
        );

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
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
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let instructions = vec![token_instruction::mint_to(
            &token_program_id,
            &token_mint,
            &associated_account,
            &self.payer,
            &[],
            amount,
        )];
        log!(
            DEBUG,
            "[solana_client::mint_to] instructions: {:?} ",
            instructions
        );

        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn update_metadata(
        &self,
        token_mint: Pubkey,
        token_info: TokenInfo,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let metadata = TokenMetadata {
            update_authority: OptionalNonZeroPubkey(self.payer.to_owned()),
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
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn transfer_to(
        &self,
        to_account: Pubkey,
        amount: u64,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
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
            )
            .await?;
        Ok(tx_hash)
    }

    async fn sign(&self, key_path: Vec<ByteBuf>, tx: Vec<u8>) -> anyhow::Result<Signature> {
        let signature = sign_with_eddsa(self.chainkey_name.clone(), key_path, tx)
            .await
            .try_into()
            .map_err(|e| anyhow!("invalid signature: {:?}", e))?;
        Ok(signature)
    }

    async fn send_raw_transaction(
        &self,
        instructions: &[Instruction],
        paths: Vec<Vec<ByteBuf>>,
        // forward: Option<String>,
    ) -> anyhow::Result<String> {
        let blockhash = self.get_latest_blockhash().await?;
        log!(
            DEBUG,
            "[solana_client::send_raw_transaction] get_latest_blockhash : {:?}",
            blockhash
        );
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

        log!(
            DEBUG,
            "[solana_client::send_raw_transaction] signed_tx : {:?} and string : {:?}",
            tx,
            tx.to_string()
        );

        let response: Result<(RpcResult<String>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_sendRawTransaction",
            (tx.to_string(), self.forward.to_owned()),
        )
        .await;
        log!(DEBUG, "sol_sendRawTransaction response: {:?}", response);
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

    pub async fn get_compute_units(
        &self,
        instructions: &[Instruction],
        paths: Vec<Vec<ByteBuf>>,
        // forward: Option<String>,
    ) -> anyhow::Result<Option<u64>> {
        // let blockhash = self.get_latest_blockhash().await?;
        // log!(
        //     DEBUG,
        //     "[solana_client::get_compute_units] get_latest_blockhash : {:?}",
        //     blockhash
        // );
        let message = Message::new(instructions.iter().as_ref(), Some(&self.payer));
        let mut tx = Transaction::new_unsigned(message);

        //TODO: sign msg without chain key
        for i in 0..paths.len() {
            let signature = self.sign(paths[i].clone(), tx.message_data()).await?;
            tx.add_signature(i, signature);
        }

        log!(
            DEBUG,
            "[solana_client::get_compute_units] signed_tx : {:?} and string : {:?}",
            tx,
            tx.to_string()
        );

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
        log!(DEBUG, "sol_getComputeUnits response: {:?}", resp);

        Ok(resp)
    }
}
