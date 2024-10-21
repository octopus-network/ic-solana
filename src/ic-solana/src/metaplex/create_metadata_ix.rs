use crate::metaplex::derive_metadata_pda;
use crate::metaplex::types::CreateArgs;
use crate::metaplex::types::DataV2;
use crate::metaplex::types::FungibleFields;
use crate::metaplex::types::TokenStandard;
use crate::metaplex::CreateBuilder;
use crate::token::program_error::ProgramError;
use crate::types::Instruction;
use crate::types::Pubkey;
use std::str::FromStr;

// const DEFAULT_COMPUTE_UNITS: u64 = 200_000;

pub struct CreateMetadataArgs {
    pub mint: String,
    pub metadata: FungibleFields,
    pub immutable: bool,
    pub payer: Pubkey,
    // pub priority: Priority,
    // pub full_compute: bool,
}

pub fn create_metadata_ix(args: CreateMetadataArgs) -> Result<Instruction, ProgramError> {
    let mint_pubkey = Pubkey::from_str(&args.mint).unwrap();
    let metadata_pubkey = derive_metadata_pda(&mint_pubkey);

    let data_v2 = DataV2 {
        name: args.metadata.name,
        symbol: args.metadata.symbol,
        uri: args.metadata.uri,
        seller_fee_basis_points: 0,
        creators: None,
        collection: None,
        uses: None,
    };

    let create_args = CreateArgs::V1 {
        name: data_v2.name,
        symbol: data_v2.symbol,
        uri: data_v2.uri,
        seller_fee_basis_points: data_v2.seller_fee_basis_points,
        creators: data_v2.creators,
        primary_sale_happened: false,
        is_mutable: !args.immutable,
        token_standard: TokenStandard::Fungible,
        collection: None,
        uses: None,
        collection_details: None,
        decimals: None,
        rule_set: None,
        print_supply: None,
    };

    let create_ix = CreateBuilder::new()
        .metadata(metadata_pubkey)
        .mint(mint_pubkey, false)
        .authority(args.payer)
        .payer(args.payer)
        .update_authority(args.payer, true)
        .create_args(create_args)
        .instruction();

    // let mut instructions = vec![];

    // instructions.push(create_ix);

    Ok(create_ix)
}
