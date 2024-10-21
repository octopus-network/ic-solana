use crate::metaplex::types::Asset;
use crate::metaplex::types::{
    AuthorizationData, CollectionDetailsToggle, CollectionToggle, Creator, Data, RuleSetToggle,
    UsesToggle,
};
use crate::types::Instruction;


use super::*;

pub struct UpdateMetaArgs {
    // pub client: Arc<RpcClient>,
    pub payer: Pubkey,
    pub mint_account: Pubkey,
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub seller_fee_basis_points: u16,
    pub creators: Option<Vec<Creator>>,
    // pub priority: Priority,
}
// Wrapper type for the UpdateV1InstructionArgs type from mpl-token-metadata since it doesn't have a `default` implementation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct V1UpdateArgs {
    pub new_update_authority: Option<Pubkey>,
    pub data: Option<Data>,
    pub primary_sale_happened: Option<bool>,
    pub is_mutable: Option<bool>,
    pub collection: CollectionToggle,
    pub collection_details: CollectionDetailsToggle,
    pub uses: UsesToggle,
    pub rule_set: RuleSetToggle,
    pub authorization_data: Option<AuthorizationData>,
}

impl Default for V1UpdateArgs {
    fn default() -> Self {
        Self {
            new_update_authority: None,
            data: None,
            primary_sale_happened: None,
            is_mutable: None,
            collection: CollectionToggle::None,
            collection_details: CollectionDetailsToggle::None,
            uses: UsesToggle::None,
            rule_set: RuleSetToggle::None,
            authorization_data: None,
        }
    }
}

impl From<V1UpdateArgs> for UpdateV1InstructionArgs {
    fn from(args: V1UpdateArgs) -> Self {
        let V1UpdateArgs {
            new_update_authority,
            data,
            primary_sale_happened,
            is_mutable,
            collection,
            collection_details,
            uses,
            rule_set,
            authorization_data,
        } = args;

        Self {
            new_update_authority,
            data,
            primary_sale_happened,
            is_mutable,
            collection,
            collection_details,
            uses,
            rule_set,
            authorization_data,
        }
    }
}

pub enum UpdateAssetArgs {
    V1 {
        payer: Option<Pubkey>,
        authority: Pubkey,
        mint: Pubkey,
        token: Option<Pubkey>,
        delegate_record: Option<Pubkey>,
        update_args: V1UpdateArgs,
        // priority: Priority,
    },
}

pub fn update_asset_v1_ix(args: UpdateMetaArgs) -> Instruction {
    // let current_md = decode_metadata_from_mint(&args.client, args.mint_account.clone())
    //     .map_err(|e| ActionError::ActionFailed(args.mint_account.to_string(), e.to_string()))?;

    // Token Metadata UpdateArgs enum.
    let mut update_args = V1UpdateArgs::default();

    let data = Data {
        name: args.name,
        symbol: args.symbol,
        uri: args.uri,
        seller_fee_basis_points: args.seller_fee_basis_points,
        creators: args.creators,
    };

    update_args.data = Some(data);

    // Metaboss UpdateAssetArgs enum.
    // let update_args = UpdateAssetArgs::V1 {
    //     payer: None,
    //     authority: args.payer,
    //     mint: args.mint_account.clone(),
    //     token: None::<Pubkey>,
    //     delegate_record: None::<Pubkey>, // Not supported yet in update.
    //     update_args,
    //     // priority: args.priority,
    // };

    let asset = Asset::new(args.mint_account);

    let update_ix = UpdateV1 {
        payer: args.payer,
        authority: args.payer,
        mint: asset.mint,
        metadata: asset.metadata,
        delegate_record: None,
        token: None,
        edition: asset.edition,
        system_program: system_program_id(),
        sysvar_instructions: sysvar_program_id(),
        authorization_rules: None,
        authorization_rules_program: None,
    }
    .instruction(update_args.into());

    update_ix
}
