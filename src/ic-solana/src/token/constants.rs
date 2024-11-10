use crate::types::Pubkey;
use serde_bytes::ByteBuf;
use std::str::FromStr;

pub fn system_program_id() -> Pubkey {
    Pubkey::from_str("11111111111111111111111111111111").unwrap()
}

pub fn compute_budget_id() -> Pubkey {
    Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap()
}

pub fn sysvar_program_id() -> Pubkey {
    Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()
}

pub fn token_program_id() -> Pubkey {
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
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

pub fn memo_program_id() -> Pubkey {
    Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap()
}

