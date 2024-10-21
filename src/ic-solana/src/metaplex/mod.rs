use std::str::FromStr;
pub mod create_fungible22_ix;
pub mod create_fungible_ix;
pub mod create_metadata_ix;
pub mod extension;
pub mod types;
pub mod update_metadata_ix;

use crate::metaplex::types::CreateArgs;
use crate::metaplex::types::{
    AuthorizationData, CollectionDetailsToggle, CollectionToggle, Data, RuleSetToggle, UsesToggle,
};
use crate::token::constants::system_program_id;
use crate::token::constants::sysvar_program_id;
use crate::types::instruction;
use crate::types::Pubkey;
// use borsh::BorshDeserialize;
// use borsh::BorshSerialize;
use borsh_derive::BorshDeserialize;
use borsh_derive::BorshSerialize;
pub const METADATA_PREFIX: &str = "metadata";
pub const TOKEN_RECORD_SEED: &str = "token_record";

pub fn metadata_program_id() -> Pubkey {
    Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").unwrap()
}

pub fn derive_metadata_pda(pubkey: &Pubkey) -> Pubkey {
    let metaplex_pubkey = metadata_program_id();

    let seeds = &[
        "metadata".as_bytes(),
        metaplex_pubkey.as_ref(),
        pubkey.as_ref(),
    ];

    let (pda, _) = Pubkey::find_program_address(seeds, &metaplex_pubkey);
    pda
}

pub fn derive_token_record_pda(mint: &Pubkey, token: &Pubkey) -> Pubkey {
    let (pda, _bump) = Pubkey::find_program_address(
        &[
            METADATA_PREFIX.as_bytes(),
            metadata_program_id().as_ref(),
            mint.as_ref(),
            TOKEN_RECORD_SEED.as_bytes(),
            token.as_ref(),
        ],
        &metadata_program_id(),
    );

    pda
}

pub fn derive_edition_pda(pubkey: &Pubkey) -> Pubkey {
    let metaplex_pubkey = metadata_program_id();

    let seeds = &[
        "metadata".as_bytes(),
        metaplex_pubkey.as_ref(),
        pubkey.as_ref(),
        "edition".as_bytes(),
    ];

    let (pda, _) = Pubkey::find_program_address(seeds, &metaplex_pubkey);
    pda
}

/// Accounts.
pub struct Create {
    /// Unallocated metadata account with address as pda of ['metadata', program id, mint id]
    pub metadata: Pubkey,
    /// Unallocated edition account with address as pda of ['metadata', program id, mint, 'edition']
    pub master_edition: Option<Pubkey>,
    /// Mint of token asset
    pub mint: (Pubkey, bool),
    /// Mint authority
    pub authority: Pubkey,
    /// Payer
    pub payer: Pubkey,
    /// Update authority for the metadata account
    pub update_authority: (Pubkey, bool),
    /// System program
    pub system_program: Pubkey,
    /// Instructions sysvar account
    pub sysvar_instructions: Pubkey,
    /// SPL Token program
    pub spl_token_program: Option<Pubkey>,
}

impl Create {
    pub fn instruction(&self, args: CreateInstructionArgs) -> instruction::Instruction {
        self.instruction_with_remaining_accounts(args, &[])
    }
    #[allow(clippy::vec_init_then_push)]
    pub fn instruction_with_remaining_accounts(
        &self,
        args: CreateInstructionArgs,
        remaining_accounts: &[instruction::AccountMeta],
    ) -> instruction::Instruction {
        let mut accounts = Vec::with_capacity(9 + remaining_accounts.len());
        accounts.push(instruction::AccountMeta::new(self.metadata, false));
        if let Some(master_edition) = self.master_edition {
            accounts.push(instruction::AccountMeta::new(master_edition, false));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        accounts.push(instruction::AccountMeta::new(self.mint.0, self.mint.1));
        accounts.push(instruction::AccountMeta::new_readonly(self.authority, true));
        accounts.push(instruction::AccountMeta::new(self.payer, true));
        accounts.push(instruction::AccountMeta::new_readonly(
            self.update_authority.0,
            self.update_authority.1,
        ));
        accounts.push(instruction::AccountMeta::new_readonly(
            self.system_program,
            false,
        ));
        accounts.push(instruction::AccountMeta::new_readonly(
            self.sysvar_instructions,
            false,
        ));
        if let Some(spl_token_program) = self.spl_token_program {
            accounts.push(instruction::AccountMeta::new_readonly(
                spl_token_program,
                false,
            ));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        accounts.extend_from_slice(remaining_accounts);
        let mut data = vec![];
        let mut create_ix_data = borsh::to_vec(&CreateInstructionData::new()).unwrap();
        data.append(&mut create_ix_data);
        let mut args = borsh::to_vec(&args).unwrap();
        data.append(&mut args);

        instruction::Instruction {
            program_id: metadata_program_id(),
            accounts,
            data,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CreateInstructionData {
    discriminator: u8,
}

impl CreateInstructionData {
    fn new() -> Self {
        Self { discriminator: 42 }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateInstructionArgs {
    pub create_args: CreateArgs,
}

/// Instruction builder for `Create`.
///
/// ### Accounts:
///
///   0. `[writable]` metadata
///   1. `[writable, optional]` master_edition
///   2. `[writable, signer]` mint
///   3. `[signer]` authority
///   4. `[writable, signer]` payer
///   5. `[signer]` update_authority
///   6. `[optional]` system_program (default to `11111111111111111111111111111111`)
///   7. `[optional]` sysvar_instructions (default to `Sysvar1nstructions1111111111111111111111111`)
///   8. `[optional]` spl_token_program
#[derive(Default)]
pub struct CreateBuilder {
    metadata: Option<Pubkey>,
    master_edition: Option<Pubkey>,
    mint: Option<(Pubkey, bool)>,
    authority: Option<Pubkey>,
    payer: Option<Pubkey>,
    update_authority: Option<(Pubkey, bool)>,
    system_program: Option<Pubkey>,
    sysvar_instructions: Option<Pubkey>,
    spl_token_program: Option<Pubkey>,
    create_args: Option<CreateArgs>,
    __remaining_accounts: Vec<instruction::AccountMeta>,
}

impl CreateBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Unallocated metadata account with address as pda of ['metadata', program id, mint id]
    #[inline(always)]
    pub fn metadata(&mut self, metadata: Pubkey) -> &mut Self {
        self.metadata = Some(metadata);
        self
    }
    /// `[optional account]`
    /// Unallocated edition account with address as pda of ['metadata', program id, mint, 'edition']
    #[inline(always)]
    pub fn master_edition(&mut self, master_edition: Option<Pubkey>) -> &mut Self {
        self.master_edition = master_edition;
        self
    }
    /// Mint of token asset
    #[inline(always)]
    pub fn mint(&mut self, mint: Pubkey, as_signer: bool) -> &mut Self {
        self.mint = Some((mint, as_signer));
        self
    }
    /// Mint authority
    #[inline(always)]
    pub fn authority(&mut self, authority: Pubkey) -> &mut Self {
        self.authority = Some(authority);
        self
    }
    /// Payer
    #[inline(always)]
    pub fn payer(&mut self, payer: Pubkey) -> &mut Self {
        self.payer = Some(payer);
        self
    }
    /// Update authority for the metadata account
    #[inline(always)]
    pub fn update_authority(&mut self, update_authority: Pubkey, as_signer: bool) -> &mut Self {
        self.update_authority = Some((update_authority, as_signer));
        self
    }
    /// `[optional account, default to '11111111111111111111111111111111']`
    /// System program
    #[inline(always)]
    pub fn system_program(&mut self, system_program: Pubkey) -> &mut Self {
        self.system_program = Some(system_program);
        self
    }
    /// `[optional account, default to 'Sysvar1nstructions1111111111111111111111111']`
    /// Instructions sysvar account
    #[inline(always)]
    pub fn sysvar_instructions(&mut self, sysvar_instructions: Pubkey) -> &mut Self {
        self.sysvar_instructions = Some(sysvar_instructions);
        self
    }
    /// `[optional account]`
    /// SPL Token program
    #[inline(always)]
    pub fn spl_token_program(&mut self, spl_token_program: Option<Pubkey>) -> &mut Self {
        self.spl_token_program = spl_token_program;
        self
    }
    #[inline(always)]
    pub fn create_args(&mut self, create_args: CreateArgs) -> &mut Self {
        self.create_args = Some(create_args);
        self
    }
    /// Add an aditional account to the instruction.
    #[inline(always)]
    pub fn add_remaining_account(&mut self, account: instruction::AccountMeta) -> &mut Self {
        self.__remaining_accounts.push(account);
        self
    }
    /// Add additional accounts to the instruction.
    #[inline(always)]
    pub fn add_remaining_accounts(&mut self, accounts: &[instruction::AccountMeta]) -> &mut Self {
        self.__remaining_accounts.extend_from_slice(accounts);
        self
    }
    #[allow(clippy::clone_on_copy)]
    pub fn instruction(&self) -> instruction::Instruction {
        let accounts = Create {
            metadata: self.metadata.expect("metadata is not set"),
            master_edition: self.master_edition,
            mint: self.mint.expect("mint is not set"),
            authority: self.authority.expect("authority is not set"),
            payer: self.payer.expect("payer is not set"),
            update_authority: self.update_authority.expect("update_authority is not set"),
            system_program: self.system_program.unwrap_or(system_program_id()),
            sysvar_instructions: self.sysvar_instructions.unwrap_or(sysvar_program_id()),
            spl_token_program: self.spl_token_program,
        };
        let args = CreateInstructionArgs {
            create_args: self.create_args.clone().expect("create_args is not set"),
        };

        accounts.instruction_with_remaining_accounts(args, &self.__remaining_accounts)
    }
}

/// Accounts.
pub struct UpdateV1 {
    /// Update authority or delegate
    pub authority: Pubkey,
    /// Delegate record PDA
    pub delegate_record: Option<Pubkey>,
    /// Token account
    pub token: Option<Pubkey>,
    /// Mint account
    pub mint: Pubkey,
    /// Metadata account
    pub metadata: Pubkey,
    /// Edition account
    pub edition: Option<Pubkey>,
    /// Payer
    pub payer: Pubkey,
    /// System program
    pub system_program: Pubkey,
    /// Instructions sysvar account
    pub sysvar_instructions: Pubkey,
    /// Token Authorization Rules Program
    pub authorization_rules_program: Option<Pubkey>,
    /// Token Authorization Rules account
    pub authorization_rules: Option<Pubkey>,
}

impl UpdateV1 {
    pub fn instruction(&self, args: UpdateV1InstructionArgs) -> instruction::Instruction {
        self.instruction_with_remaining_accounts(args, &[])
    }
    #[allow(clippy::vec_init_then_push)]
    pub fn instruction_with_remaining_accounts(
        &self,
        args: UpdateV1InstructionArgs,
        remaining_accounts: &[instruction::AccountMeta],
    ) -> instruction::Instruction {
        let mut accounts = Vec::with_capacity(11 + remaining_accounts.len());
        accounts.push(instruction::AccountMeta::new_readonly(self.authority, true));
        if let Some(delegate_record) = self.delegate_record {
            accounts.push(instruction::AccountMeta::new_readonly(
                delegate_record,
                false,
            ));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        if let Some(token) = self.token {
            accounts.push(instruction::AccountMeta::new_readonly(token, false));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        accounts.push(instruction::AccountMeta::new_readonly(self.mint, false));
        accounts.push(instruction::AccountMeta::new(self.metadata, false));
        if let Some(edition) = self.edition {
            accounts.push(instruction::AccountMeta::new_readonly(edition, false));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        accounts.push(instruction::AccountMeta::new(self.payer, true));
        accounts.push(instruction::AccountMeta::new_readonly(
            self.system_program,
            false,
        ));
        accounts.push(instruction::AccountMeta::new_readonly(
            self.sysvar_instructions,
            false,
        ));
        if let Some(authorization_rules_program) = self.authorization_rules_program {
            accounts.push(instruction::AccountMeta::new_readonly(
                authorization_rules_program,
                false,
            ));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        if let Some(authorization_rules) = self.authorization_rules {
            accounts.push(instruction::AccountMeta::new_readonly(
                authorization_rules,
                false,
            ));
        } else {
            accounts.push(instruction::AccountMeta::new_readonly(
                metadata_program_id(),
                false,
            ));
        }
        accounts.extend_from_slice(remaining_accounts);
        let mut data = borsh::to_vec(&UpdateV1InstructionData::new()).unwrap();
        let mut args = borsh::to_vec(&args).unwrap();
        data.append(&mut args);

        instruction::Instruction {
            program_id: metadata_program_id(),
            accounts,
            data,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct UpdateV1InstructionData {
    discriminator: u8,
    update_v1_discriminator: u8,
}

impl UpdateV1InstructionData {
    fn new() -> Self {
        Self {
            discriminator: 50,
            update_v1_discriminator: 0,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateV1InstructionArgs {
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

/// Instruction builder for `UpdateV1`.
///
/// ### Accounts:
///
///   0. `[signer]` authority
///   1. `[optional]` delegate_record
///   2. `[optional]` token
///   3. `[]` mint
///   4. `[writable]` metadata
///   5. `[optional]` edition
///   6. `[writable, signer]` payer
///   7. `[optional]` system_program (default to `11111111111111111111111111111111`)
///   8. `[optional]` sysvar_instructions (default to `Sysvar1nstructions1111111111111111111111111`)
///   9. `[optional]` authorization_rules_program
///   10. `[optional]` authorization_rules
#[derive(Default)]
pub struct UpdateV1Builder {
    authority: Option<Pubkey>,
    delegate_record: Option<Pubkey>,
    token: Option<Pubkey>,
    mint: Option<Pubkey>,
    metadata: Option<Pubkey>,
    edition: Option<Pubkey>,
    payer: Option<Pubkey>,
    system_program: Option<Pubkey>,
    sysvar_instructions: Option<Pubkey>,
    authorization_rules_program: Option<Pubkey>,
    authorization_rules: Option<Pubkey>,
    new_update_authority: Option<Pubkey>,
    data: Option<Data>,
    primary_sale_happened: Option<bool>,
    is_mutable: Option<bool>,
    collection: Option<CollectionToggle>,
    collection_details: Option<CollectionDetailsToggle>,
    uses: Option<UsesToggle>,
    rule_set: Option<RuleSetToggle>,
    authorization_data: Option<AuthorizationData>,
    __remaining_accounts: Vec<instruction::AccountMeta>,
}

impl UpdateV1Builder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Update authority or delegate
    #[inline(always)]
    pub fn authority(&mut self, authority: Pubkey) -> &mut Self {
        self.authority = Some(authority);
        self
    }
    /// `[optional account]`
    /// Delegate record PDA
    #[inline(always)]
    pub fn delegate_record(&mut self, delegate_record: Option<Pubkey>) -> &mut Self {
        self.delegate_record = delegate_record;
        self
    }
    /// `[optional account]`
    /// Token account
    #[inline(always)]
    pub fn token(&mut self, token: Option<Pubkey>) -> &mut Self {
        self.token = token;
        self
    }
    /// Mint account
    #[inline(always)]
    pub fn mint(&mut self, mint: Pubkey) -> &mut Self {
        self.mint = Some(mint);
        self
    }
    /// Metadata account
    #[inline(always)]
    pub fn metadata(&mut self, metadata: Pubkey) -> &mut Self {
        self.metadata = Some(metadata);
        self
    }
    /// `[optional account]`
    /// Edition account
    #[inline(always)]
    pub fn edition(&mut self, edition: Option<Pubkey>) -> &mut Self {
        self.edition = edition;
        self
    }
    /// Payer
    #[inline(always)]
    pub fn payer(&mut self, payer: Pubkey) -> &mut Self {
        self.payer = Some(payer);
        self
    }
    /// `[optional account, default to '11111111111111111111111111111111']`
    /// System program
    #[inline(always)]
    pub fn system_program(&mut self, system_program: Pubkey) -> &mut Self {
        self.system_program = Some(system_program);
        self
    }
    /// `[optional account, default to 'Sysvar1nstructions1111111111111111111111111']`
    /// Instructions sysvar account
    #[inline(always)]
    pub fn sysvar_instructions(&mut self, sysvar_instructions: Pubkey) -> &mut Self {
        self.sysvar_instructions = Some(sysvar_instructions);
        self
    }
    /// `[optional account]`
    /// Token Authorization Rules Program
    #[inline(always)]
    pub fn authorization_rules_program(
        &mut self,
        authorization_rules_program: Option<Pubkey>,
    ) -> &mut Self {
        self.authorization_rules_program = authorization_rules_program;
        self
    }
    /// `[optional account]`
    /// Token Authorization Rules account
    #[inline(always)]
    pub fn authorization_rules(&mut self, authorization_rules: Option<Pubkey>) -> &mut Self {
        self.authorization_rules = authorization_rules;
        self
    }
    /// `[optional argument]`
    #[inline(always)]
    pub fn new_update_authority(&mut self, new_update_authority: Pubkey) -> &mut Self {
        self.new_update_authority = Some(new_update_authority);
        self
    }
    /// `[optional argument]`
    #[inline(always)]
    pub fn data(&mut self, data: Data) -> &mut Self {
        self.data = Some(data);
        self
    }
    /// `[optional argument]`
    #[inline(always)]
    pub fn primary_sale_happened(&mut self, primary_sale_happened: bool) -> &mut Self {
        self.primary_sale_happened = Some(primary_sale_happened);
        self
    }
    /// `[optional argument]`
    #[inline(always)]
    pub fn is_mutable(&mut self, is_mutable: bool) -> &mut Self {
        self.is_mutable = Some(is_mutable);
        self
    }
    /// `[optional argument, defaults to 'CollectionToggle::None']`
    #[inline(always)]
    pub fn collection(&mut self, collection: CollectionToggle) -> &mut Self {
        self.collection = Some(collection);
        self
    }
    /// `[optional argument, defaults to 'CollectionDetailsToggle::None']`
    #[inline(always)]
    pub fn collection_details(&mut self, collection_details: CollectionDetailsToggle) -> &mut Self {
        self.collection_details = Some(collection_details);
        self
    }
    /// `[optional argument, defaults to 'UsesToggle::None']`
    #[inline(always)]
    pub fn uses(&mut self, uses: UsesToggle) -> &mut Self {
        self.uses = Some(uses);
        self
    }
    /// `[optional argument, defaults to 'RuleSetToggle::None']`
    #[inline(always)]
    pub fn rule_set(&mut self, rule_set: RuleSetToggle) -> &mut Self {
        self.rule_set = Some(rule_set);
        self
    }
    /// `[optional argument]`
    #[inline(always)]
    pub fn authorization_data(&mut self, authorization_data: AuthorizationData) -> &mut Self {
        self.authorization_data = Some(authorization_data);
        self
    }
    /// Add an aditional account to the instruction.
    #[inline(always)]
    pub fn add_remaining_account(&mut self, account: instruction::AccountMeta) -> &mut Self {
        self.__remaining_accounts.push(account);
        self
    }
    /// Add additional accounts to the instruction.
    #[inline(always)]
    pub fn add_remaining_accounts(&mut self, accounts: &[instruction::AccountMeta]) -> &mut Self {
        self.__remaining_accounts.extend_from_slice(accounts);
        self
    }
    #[allow(clippy::clone_on_copy)]
    pub fn instruction(&self) -> instruction::Instruction {
        let accounts = UpdateV1 {
            authority: self.authority.expect("authority is not set"),
            delegate_record: self.delegate_record,
            token: self.token,
            mint: self.mint.expect("mint is not set"),
            metadata: self.metadata.expect("metadata is not set"),
            edition: self.edition,
            payer: self.payer.expect("payer is not set"),
            system_program: self.system_program.unwrap_or(system_program_id()),
            sysvar_instructions: self.sysvar_instructions.unwrap_or(sysvar_program_id()),
            authorization_rules_program: self.authorization_rules_program,
            authorization_rules: self.authorization_rules,
        };
        let args = UpdateV1InstructionArgs {
            new_update_authority: self.new_update_authority.clone(),
            data: self.data.clone(),
            primary_sale_happened: self.primary_sale_happened.clone(),
            is_mutable: self.is_mutable.clone(),
            collection: self.collection.clone().unwrap_or(CollectionToggle::None),
            collection_details: self
                .collection_details
                .clone()
                .unwrap_or(CollectionDetailsToggle::None),
            uses: self.uses.clone().unwrap_or(UsesToggle::None),
            rule_set: self.rule_set.clone().unwrap_or(RuleSetToggle::None),
            authorization_data: self.authorization_data.clone(),
        };

        accounts.instruction_with_remaining_accounts(args, &self.__remaining_accounts)
    }
}
