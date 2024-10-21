use crate::metaplex::derive_edition_pda;
use crate::metaplex::derive_metadata_pda;
use crate::metaplex::derive_token_record_pda;
use crate::types::Pubkey;
// use borsh::BorshDeserialize;
// use borsh::BorshSerialize;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use serde_derive::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct FungibleFields {
    pub name: String,
    pub symbol: String,
    pub uri: String,
}

impl From<FungibleFields> for DataV2 {
    fn from(value: FungibleFields) -> Self {
        DataV2 {
            name: value.name,
            symbol: value.symbol,
            uri: value.uri,
            seller_fee_basis_points: 0,
            creators: None,
            collection: None,
            uses: None,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataV2 {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub seller_fee_basis_points: u16,
    pub creators: Option<Vec<Creator>>,
    pub collection: Option<Collection>,
    pub uses: Option<Uses>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Collection {
    pub verified: bool,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::As::<serde_with::DisplayFromStr>")
    )]
    pub key: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CollectionDetails {
    V1 { size: u64 },
    V2 { padding: [u8; 8] },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Creator {
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::As::<serde_with::DisplayFromStr>")
    )]
    pub address: Pubkey,
    pub verified: bool,
    pub share: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Uses {
    pub use_method: UseMethod,
    pub remaining: u64,
    pub total: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UseMethod {
    Burn,
    Multiple,
    Single,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PrintSupply {
    Zero,
    Limited(u64),
    Unlimited,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TokenStandard {
    NonFungible,
    FungibleAsset,
    Fungible,
    NonFungibleEdition,
    ProgrammableNonFungible,
    ProgrammableNonFungibleEdition,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CreateArgs {
    V1 {
        name: String,
        symbol: String,
        uri: String,
        seller_fee_basis_points: u16,
        creators: Option<Vec<Creator>>,
        primary_sale_happened: bool,
        is_mutable: bool,
        token_standard: TokenStandard,
        collection: Option<Collection>,
        uses: Option<Uses>,
        collection_details: Option<CollectionDetails>,
        rule_set: Option<Pubkey>,
        decimals: Option<u8>,
        print_supply: Option<PrintSupply>,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Data {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub seller_fee_basis_points: u16,
    pub creators: Option<Vec<Creator>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CollectionToggle {
    None,
    Clear,
    Set(Collection),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CollectionDetailsToggle {
    None,
    Clear,
    Set(CollectionDetails),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UsesToggle {
    None,
    Clear,
    Set(Uses),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RuleSetToggle {
    None,
    Clear,
    Set(Pubkey),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthorizationData {
    pub payload: Payload,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Payload {
    pub map: HashMap<String, PayloadType>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PayloadType {
    Pubkey(Pubkey),
    Seeds(SeedsVec),
    MerkleProof(ProofInfo),
    Number(u64),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SeedsVec {
    pub seeds: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofInfo {
    pub proof: Vec<[u8; 32]>,
}

pub type MintAddress = String;
pub type NetworkError = String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UpdateError {
    #[error("Action failed with error: {1}")]
    UpdateFailed(MintAddress, NetworkError),
}

#[derive(Error, Debug)]
pub enum ActionError {
    #[error("Action failed with error: {1}")]
    ActionFailed(MintAddress, NetworkError),
}

pub struct Asset {
    pub mint: Pubkey,
    pub metadata: Pubkey,
    pub edition: Option<Pubkey>,
}

impl Asset {
    pub fn new(mint: Pubkey) -> Self {
        let metadata = derive_metadata_pda(&mint);

        Self {
            mint,
            metadata,
            edition: None,
        }
    }

    pub fn add_edition(&mut self) {
        self.edition = Some(derive_edition_pda(&self.mint));
    }

    pub fn get_token_record(&self, token: &Pubkey) -> Pubkey {
        derive_token_record_pda(&self.mint, token)
    }

    // pub fn get_metadata(&self, client: &RpcClient) -> Result<Metadata, DecodeError> {
    //     decode_metadata(client, &self.metadata)
    // }

    // pub(crate) fn _get_token_owner(client: &RpcClient, token: &Pubkey) -> Result<Pubkey> {
    //     let data = client.get_account_data(token)?;
    //     let owner = TokenAccount::unpack(&data)?.owner;
    //     Ok(owner)
    // }
}
