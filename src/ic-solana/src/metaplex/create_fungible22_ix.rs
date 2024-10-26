use crate::metaplex::extension::ExtensionType;

use crate::token::constants::token22_program_id;

use crate::token::system_instruction::create_account;
use crate::token::token_instruction::initialize_metadata_pointer;
use crate::token::token_instruction::initialize_mint2;
use crate::token::token_instruction::initialize_mint_close_authority;
use crate::token::token_metadata::initialize as initialize_metadata;
use crate::token::token_metadata::update_field as add_additional_metadata;
use crate::token::token_metadata::Field;

use crate::types::Instruction;
use crate::types::Pubkey;

use serde_derive::Deserialize;
use std::str::FromStr;
pub struct CreateFungible22Args {
    pub mint: Pubkey,
    pub extensions: Fungible22Fields,
    pub mint_size: u64,
    pub mint_rent: u64,
    pub decimals: u8,
    pub payer: Pubkey,
    // pub mint_path: Option<String>,
    // pub initial_supply: Option<u64>,
    // pub priority: Priority,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TransferFeeConfig {
    pub transfer_fee_config_authority: Option<String>,
    pub withdraw_withheld_authority: Option<String>,
    pub fee_basis_points: u16,
    pub max_fee: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct InterestBearingConfig {
    pub rate_authority: Option<String>,
    pub rate: i16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TransferHookConfig {
    pub program_id: Option<String>,
    pub authority: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MetadataConfig {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub additional_metadata: Option<Vec<[String; 2]>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Fungible22Fields {
    pub metadata: Option<MetadataConfig>,
    pub close_authority: Option<String>,
    pub permanent_delegate: Option<String>,
    pub non_transferrable: Option<bool>,
    pub transfer_fee: Option<TransferFeeConfig>,
    pub interest_bearing: Option<InterestBearingConfig>,
    pub transfer_hook: Option<TransferHookConfig>,
}

pub fn create_fungible_22_ix(args: CreateFungible22Args) -> Vec<Instruction> {
    let is_close_authority = args.extensions.close_authority.is_some();

    let is_metadata = args.extensions.metadata.is_some();

    let mut extension_types = vec![];

    // Adding extensions
    if is_close_authority {
        extension_types.push(ExtensionType::MintCloseAuthority);
    }

    let mut instructions = vec![];

    let create_mint_account_ix = create_account(
        &args.payer,
        &args.mint,
        args.mint_rent,
        args.mint_size,
        &token22_program_id(),
    );
    instructions.push(create_mint_account_ix);

    // Initialize extensions
    if is_metadata {
        let init_metadata_pointer_ix =
            initialize_metadata_pointer(&args.mint, &args.mint,&args.payer);
        instructions.push(init_metadata_pointer_ix);
    }

    if let Some(close_authority) = args.extensions.close_authority {
        let close_authority = Pubkey::from_str(&close_authority).unwrap();
        let init_close_authority_ix =
            initialize_mint_close_authority(&args.mint, Some(&close_authority));
        instructions.push(init_close_authority_ix);
    }

    // Initialize mint
    let initialize_mint_ix = initialize_mint2(
        &token22_program_id(),
        &args.mint,
        &args.payer,
        Some(&args.payer),
        args.decimals,
    );
    instructions.push(initialize_mint_ix);

    // Initialize metadata
    if let Some(MetadataConfig {
        name,
        uri,
        symbol,
        additional_metadata,
    }) = args.extensions.metadata
    {
        let init_metadata_ix = initialize_metadata(
            &token22_program_id(),
            &args.mint,
            &args.payer,
            &args.mint,
            &args.payer,
            name,
            symbol,
            uri,
        );
        instructions.push(init_metadata_ix);

        if let Some(additional_metadata) = additional_metadata {
            for field_value_pair in additional_metadata {
                let add_additional_metadata_ix = add_additional_metadata(
                    &token22_program_id(),
                    &args.mint,
                    &args.payer,
                    Field::Key(field_value_pair[0].clone()),
                    field_value_pair[1].clone(),
                );
                instructions.push(add_additional_metadata_ix);
            }
        }
    }

    instructions
}
