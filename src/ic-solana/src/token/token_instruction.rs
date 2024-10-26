use crate::token::system_instruction::SYSVAR_ID;
use crate::types::{AccountMeta, Instruction, Pubkey};
use std::str::FromStr;

use super::constants::token22_program_id;

/// Creates a `InitializeMint` instruction.
pub fn initialize_mint(
    token_program_id: &Pubkey,
    mint_pubkey: &Pubkey,
    mint_authority_pubkey: &Pubkey,
    freeze_authority_pubkey: Option<&Pubkey>,
    decimals: u8,
) -> Instruction {
    let mut data: Vec<u8> = vec![];
    data.push(0);
    data.push(decimals);
    data.extend_from_slice(mint_authority_pubkey.as_ref());
    match freeze_authority_pubkey {
        None => {
            data.push(0);
        }
        Some(p) => {
            data.push(1);
            data.extend_from_slice(&p.to_bytes());
        }
    }
    let pubkey = Pubkey::from_str(SYSVAR_ID).unwrap();
    let accounts = vec![
        AccountMeta::new(*mint_pubkey, false),
        AccountMeta::new_readonly(pubkey, false),
    ];
    Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    }
}

/// Creates a `InitializeMint2` instruction.
/// Like InitializeMint, but does not require the Rent sysvar to be provided
pub fn initialize_mint2(
    token_program_id: &Pubkey,
    mint_pubkey: &Pubkey,
    mint_authority_pubkey: &Pubkey,
    freeze_authority_pubkey: Option<&Pubkey>,
    decimals: u8,
) -> Instruction {
    let mut data: Vec<u8> = vec![];
    data.push(20);
    data.push(decimals);
    data.extend_from_slice(mint_authority_pubkey.as_ref());
    match freeze_authority_pubkey {
        None => {
            data.push(0);
        }
        Some(p) => {
            data.push(1);
            data.extend_from_slice(&p.to_bytes());
        }
    }

    let accounts = vec![AccountMeta::new(*mint_pubkey, false)];
    Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    }
}

/// Creates a `MintTo` instruction.
pub fn mint_to(
    token_program_id: &Pubkey,
    mint_pubkey: &Pubkey,
    account_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    signer_pubkeys: &[&Pubkey],
    amount: u64,
) -> Instruction {
    // check_spl_token_program_account(token_program_id)?;
    let mut data: Vec<u8> = vec![];
    data.push(7);
    data.extend_from_slice(&amount.to_le_bytes());

    let mut accounts = Vec::with_capacity(3 + signer_pubkeys.len());
    accounts.push(AccountMeta::new(*mint_pubkey, false));
    accounts.push(AccountMeta::new(*account_pubkey, false));
    accounts.push(AccountMeta::new_readonly(
        *owner_pubkey,
        signer_pubkeys.is_empty(),
    ));
    for signer_pubkey in signer_pubkeys.iter() {
        accounts.push(AccountMeta::new_readonly(**signer_pubkey, true));
    }

    Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    }
}

pub fn initialize_mint_close_authority(
    token_mint: &Pubkey,
    close_authority: Option<&Pubkey>,
) -> Instruction {
    let mut data: Vec<u8> = Vec::new();
    data.push(25u8);

    match close_authority {
        Some(p) => {
            data.push(1);
            data.extend_from_slice(&p.to_bytes());
        }
        None => {
            data.push(0);
        }
    }

    let accounts = vec![AccountMeta::new(*token_mint, false)];
    Instruction {
        program_id: token22_program_id(),
        accounts,
        data,
    }
}

pub fn initialize_metadata_pointer(
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

/// Creates a `CloseAccount` instruction.
/// Close an account by transferring all its SOL to the destination account.
/// Non-native accounts may only be closed if its token amount is zero.
///
/// Accounts expected by this instruction:
///
///   * Single owner
///   0. `[writable]` The account to close.
///   1. `[writable]` The destination account.
///   2. `[signer]` The account's owner.
///
///   * Multisignature owner
///   0. `[writable]` The account to close.
///   1. `[writable]` The destination account.
///   2. `[]` The account's multisignature owner.
///   3. ..3+M `[signer]` M signer accounts.
pub fn close_account(
    token_program_id: &Pubkey,
    account_pubkey: &Pubkey,
    destination_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    signer_pubkeys: &[&Pubkey],
) -> Instruction {
    let mut data: Vec<u8> = vec![];
    data.push(9);
    let mut accounts = Vec::with_capacity(3 + signer_pubkeys.len());
    accounts.push(AccountMeta::new(*account_pubkey, false));
    accounts.push(AccountMeta::new(*destination_pubkey, false));
    accounts.push(AccountMeta::new_readonly(
        *owner_pubkey,
        signer_pubkeys.is_empty(),
    ));
    for signer_pubkey in signer_pubkeys.iter() {
        accounts.push(AccountMeta::new_readonly(**signer_pubkey, true));
    }

    Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    }
}

/// Creates a `FreezeAccount` instruction.
/// Freeze an Initialized account using the Mint's freeze_authority (if
/// set).
///
/// Accounts expected by this instruction:
///
///   * Single owner
///   0. `[writable]` The account to freeze.
///   1. `[]` The token mint.
///   2. `[signer]` The mint freeze authority.
///
///   * Multisignature owner
///   0. `[writable]` The account to freeze.
///   1. `[]` The token mint.
///   2. `[]` The mint's multisignature freeze authority.
///   3. ..3+M `[signer]` M signer accounts.
pub fn freeze_account(
    token_program_id: &Pubkey,
    account_pubkey: &Pubkey,
    mint_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    signer_pubkeys: &[&Pubkey],
) -> Instruction {
    let mut data: Vec<u8> = vec![];
    data.push(10);
    let mut accounts = Vec::with_capacity(3 + signer_pubkeys.len());
    accounts.push(AccountMeta::new(*account_pubkey, false));
    accounts.push(AccountMeta::new_readonly(*mint_pubkey, false));
    accounts.push(AccountMeta::new_readonly(
        *owner_pubkey,
        signer_pubkeys.is_empty(),
    ));
    for signer_pubkey in signer_pubkeys.iter() {
        accounts.push(AccountMeta::new_readonly(**signer_pubkey, true));
    }

    Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    }
}
