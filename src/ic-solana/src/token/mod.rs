use crate::eddsa::{eddsa_public_key, sign_with_eddsa};
use crate::rpc_client::{RpcError, RpcResult};
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
        let response: Result<(RpcResult<String>,), _> =
            ic_cdk::call(self.sol_canister_id, "sol_getTransaction", (txhash,)).await;
        let tx = response
            .map_err(|e| anyhow!(format!("query transaction err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("query transaction rpc error: {:?}", e)))?;
        let tx = serde_json::from_str(tx.as_str()).unwrap();
        Ok(tx)
    }

    // parse the redeem transaction via signatrure,return (transition fee info (sender,receiver and amount) ,burned info (account and amount),receiver include memo)
    //
    pub async fn parse_redeem_transaction(
        &self,
        signature: String,
    ) -> anyhow::Result<EncodedConfirmedTransactionWithStatusMeta> {
        let response: Result<(RpcResult<String>,), _> =
            ic_cdk::call(self.sol_canister_id, "sol_getTransaction", (signature,)).await;
        let tx = response
            .map_err(|e| anyhow!(format!("call sol_getTransaction err: {:?}", e)))?
            .0
            .map_err(|e| anyhow!(format!("sol_getTransaction rpc error: {:?}", e)))?;
        let tx = serde_json::from_str(tx.as_str()).unwrap();
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
        associated_token_account: Pubkey,
        amount: u64,
        token_mint: Pubkey,
    ) -> anyhow::Result<String> {
        // let associated_token_account = self.associated_account(&to_account, &token_mint).await?;
        // ic_cdk::println!(
        //     "{:?} for {:?} associated token account: {:?} ",
        //     to_account.to_string(),
        //     token_mint.to_string(),
        //     associated_token_account.to_string()
        // );
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

        ic_cdk::println!(
            "{:?} for {:?} associated token account: {:?} ",
            owner.to_string(),
            token_mint.to_string(),
            associated_account.to_string()
        );

        let r: Result<(RpcResult<Option<Account>>,), _> = ic_cdk::call(
            self.sol_canister_id,
            "sol_getAccountInfo",
            (associated_account.to_string(),),
        )
        .await;
        let resp = r
            .map_err(|e| anyhow!(format!("call sol_getAccountInfo error: {:?}", e)))?
            .0
            .map_err(|e| {
                // match e {
                //     RpcError::Text()
                // }
                anyhow!(format!("query account info rpc error:{:?}", e))
            })?;
        match resp {
            None => {
                //create_account
                self.create_associated_token_account(owner, token_mint)
                    .await?;
                Ok(associated_account)
            }
            //TODO: check already contain the associated_account ?
            Some(_) => Ok(associated_account),
        }
    }

    pub async fn create_associated_token_account(
        &self,
        owner_addr: &Pubkey,
        token_mint: &Pubkey,
    ) -> anyhow::Result<String> {
        let instructions = vec![
            crate::token::associated_account::create_associated_token_account(
                &self.payer,
                &owner_addr,
                &token_mint,
                &token22_program_id(),
            ),
        ];
        let tx_hash = self
            .send_raw_transaction(
                instructions.as_slice(),
                vec![self.payer_derive_path.clone()],
            )
            .await?;
        Ok(tx_hash)
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
        .map_err(|e| anyhow!("invalid signature: {:?}", e))?;
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
