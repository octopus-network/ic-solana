use crate::types::Pubkey;
use serde_bytes::ByteBuf;
use std::str::FromStr;

pub fn system_program_id() -> Pubkey {
    Pubkey::from_str("11111111111111111111111111111111").unwrap()
}

pub fn token22_program_id() -> Pubkey {
    Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap()
}

pub fn associated_account_program_id() -> Pubkey {
    Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
}

pub fn route_signer_derive_path() -> Vec<ByteBuf> {
    vec![ByteBuf::from("custom_addr")]
}
