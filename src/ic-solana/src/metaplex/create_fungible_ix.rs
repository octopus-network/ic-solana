use crate::metaplex::derive_metadata_pda;
use crate::metaplex::types::CreateArgs;

use crate::metaplex::types::FungibleFields;
use crate::metaplex::types::TokenStandard;
use crate::metaplex::CreateBuilder;
use crate::token::constants::token_program_id;

use crate::types::Instruction;
use crate::types::Pubkey;

pub struct CreateFungibleArgs {
    pub mint: Pubkey,
    pub metadata: FungibleFields,
    pub decimals: u8,
    pub immutable: bool,
    pub payer: Pubkey,
    // pub initial_supply: Option<f64>,
    // pub priority: Priority,
    // pub full_compute: bool,
}

pub fn create_fungible_ix(args: CreateFungibleArgs) -> Instruction {
    let metadata_pubkey = derive_metadata_pda(&args.mint);

    let create_args = CreateArgs::V1 {
        name: args.metadata.name,
        symbol: args.metadata.symbol,
        uri: args.metadata.uri,
        seller_fee_basis_points: 0,
        creators: None,
        primary_sale_happened: false,
        is_mutable: !args.immutable,
        token_standard: TokenStandard::Fungible,
        collection: None,
        uses: None,
        collection_details: None,
        decimals: Some(args.decimals),
        rule_set: None,
        print_supply: None,
    };

    let create_ix = CreateBuilder::new()
        .metadata(metadata_pubkey)
        .mint(args.mint, true)
        .authority(args.payer)
        .payer(args.payer)
        .update_authority(args.payer, true)
        .create_args(create_args)
        .spl_token_program(Some(token_program_id()))
        .instruction();

    create_ix
}
