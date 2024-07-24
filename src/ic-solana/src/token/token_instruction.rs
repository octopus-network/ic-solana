use crate::token::program_error::ProgramError;
use crate::token::system_instruction::SYSVAR_ID;
use crate::types::{AccountMeta, Instruction, Pubkey};
use std::str::FromStr;

/// Creates a `InitializeMint` instruction.
pub fn initialize_mint(
    token_program_id: &Pubkey,
    mint_pubkey: &Pubkey,
    mint_authority_pubkey: &Pubkey,
    freeze_authority_pubkey: Option<&Pubkey>,
    decimals: u8,
) -> Result<Instruction, ProgramError> {
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
    Ok(Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    })
}

/// Creates a `MintTo` instruction.
pub fn mint_to(
    token_program_id: &Pubkey,
    mint_pubkey: &Pubkey,
    account_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    signer_pubkeys: &[&Pubkey],
    amount: u64,
) -> Result<Instruction, ProgramError> {
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

    Ok(Instruction {
        program_id: *token_program_id,
        accounts,
        data,
    })
}
