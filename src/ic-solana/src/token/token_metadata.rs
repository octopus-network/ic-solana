use crate::token::program_error::ProgramError;
use crate::types::{AccountMeta, Instruction, Pubkey};
use borsh_derive::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct OptionalNonZeroPubkey(pub Pubkey);

#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct TokenMetadata {
    /// The authority that can sign to update the metadata
    pub update_authority: OptionalNonZeroPubkey,
    /// The associated mint, used to counter spoofing to be sure that metadata
    /// belongs to a particular mint
    pub mint: Pubkey,
    /// The longer name of the token
    pub name: String,
    /// The shortened symbol for the token
    pub symbol: String,
    /// The URI pointing to richer metadata
    pub uri: String,
    /// Any additional metadata about the token as key-value pairs. The program
    /// must avoid storing the same key twice.
    pub additional_metadata: Vec<(String, String)>,
}

impl TokenMetadata {
    /// Gives the total size of this struct as a TLV entry in an account
    pub fn tlv_size_of(&self) -> Result<usize, ProgramError> {
        0usize
            .checked_add(get_instance_packed_len(self).unwrap())
            .ok_or(ProgramError::InvalidAccountData)
    }
}

#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Initialize {
    /// Longer name of the token
    pub name: String,
    /// Shortened symbol of the token
    pub symbol: String,
    /// URI pointing to more metadata (image, video, etc.)
    pub uri: String,
}

/// Creates an `Initialize` instruction
#[allow(clippy::too_many_arguments)]
pub fn initialize(
    program_id: &Pubkey,
    metadata: &Pubkey,
    update_authority: &Pubkey,
    mint: &Pubkey,
    mint_authority: &Pubkey,
    name: String,
    symbol: String,
    uri: String,
) -> Instruction {
    let init = Initialize { name, symbol, uri };
    let mut data: Vec<u8> = vec![210, 225, 30, 162, 88, 184, 77, 141];
    data.append(&mut borsh::to_vec(&init).unwrap());
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*metadata, false),
            AccountMeta::new_readonly(*update_authority, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*mint_authority, true),
        ],
        data,
    }
}

/// Update field instruction data

#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct UpdateField {
    /// Field to update in the metadata
    pub field: Field,
    /// Value to write for the field
    pub value: String,
}
/// Fields in the metadata account, used for updating
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum Field {
    /// The name field, corresponding to `TokenMetadata.name`
    Name,
    /// The symbol field, corresponding to `TokenMetadata.symbol`
    Symbol,
    /// The uri field, corresponding to `TokenMetadata.uri`
    Uri,
    /// A user field, whose key is given by the associated string
    Key(String),
}

/// Creates an `UpdateField` instruction
pub fn update_field(
    program_id: &Pubkey,
    metadata: &Pubkey,
    update_authority: &Pubkey,
    field: Field,
    value: String,
) -> Instruction {
    let update_field = UpdateField { field, value };
    // build discriminator
    // let preimage = hash::hashv(&[format!("{NAMESPACE}:updating_field").as_bytes()]);
    //     let discriminator =
    //         ArrayDiscriminator::try_from(&preimage.as_ref()[..ArrayDiscriminator::LENGTH]).unwrap();
    let mut data: Vec<u8> = vec![221, 233, 49, 45, 181, 202, 220, 200];
    data.append(&mut borsh::to_vec(&update_field).unwrap());
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*metadata, false),
            AccountMeta::new_readonly(*update_authority, true),
        ],
        data,
    }
}

macro_rules! impl_get_instance_packed_len {
    ($borsh:ident, $borsh_io:ident $(,#[$meta:meta])?) => {
        /// Helper struct which to count how much data would be written during serialization
        #[derive(Default)]
        struct WriteCounter {
            count: usize,
        }

        impl $borsh_io::Write for WriteCounter {
            fn write(&mut self, data: &[u8]) -> Result<usize, $borsh_io::Error> {
                let amount = data.len();
                self.count += amount;
                Ok(amount)
            }

            fn flush(&mut self) -> Result<(), $borsh_io::Error> {
                Ok(())
            }
        }

        /// Get the packed length for the serialized form of this object instance.
        ///
        /// Useful when working with instances of types that contain a variable-length
        /// sequence, such as a Vec or HashMap.  Since it is impossible to know the packed
        /// length only from the type's schema, this can be used when an instance already
        /// exists, to figure out how much space to allocate in an account.
        $(#[$meta])?
        pub fn get_instance_packed_len<T: $borsh::BorshSerialize>(instance: &T) -> Result<usize, $borsh_io::Error> {
            let mut counter = WriteCounter::default();
            instance.serialize(&mut counter)?;
            Ok(counter.count)
        }
    }
}
pub(crate) use impl_get_instance_packed_len;

use borsh::io;
impl_get_instance_packed_len!(borsh, io);
