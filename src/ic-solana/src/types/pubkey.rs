use borsh_derive::{BorshDeserialize, BorshSerialize};
use candid::CandidType;
use ic_crypto_ed25519::PublicKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{fmt, mem};
use thiserror::Error;

/// Number of bytes in a pubkey
pub const PUBKEY_BYTES: usize = 32;
/// maximum length of derived `Pubkey` seed
pub const MAX_SEED_LEN: usize = 32;
/// Maximum number of seeds
pub const MAX_SEEDS: usize = 16;
/// Maximum string length of a base58 encoded pubkey
const MAX_BASE58_LEN: usize = 44;

const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    CandidType,
)]
pub struct Pubkey(pub(crate) [u8; PUBKEY_BYTES]);

#[derive(Error, Debug, Serialize, Clone, PartialEq, Eq)]
pub enum ParsePubkeyError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base58 string")]
    Invalid,
}

impl Pubkey {
    pub fn new(key: [u8; PUBKEY_BYTES]) -> Self {
        Self(key)
    }

    pub fn to_bytes(self) -> [u8; PUBKEY_BYTES] {
        self.0
    }

    /// Verify an Ed25519 signature
    ///
    /// Returns Ok if the signature is valid, or Err otherwise
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> bool {
        let pubkey = PublicKey::deserialize_raw(&self.0).expect("invalid public key");
        pubkey.verify_signature(msg, signature).is_ok()
    }
}

impl FromStr for Pubkey {
    type Err = ParsePubkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_LEN {
            return Err(ParsePubkeyError::WrongSize);
        }
        let pubkey_vec = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParsePubkeyError::Invalid)?;
        if pubkey_vec.len() != mem::size_of::<Pubkey>() {
            Err(ParsePubkeyError::WrongSize)
        } else {
            Pubkey::try_from(pubkey_vec).map_err(|_| ParsePubkeyError::Invalid)
        }
    }
}

impl From<[u8; PUBKEY_BYTES]> for Pubkey {
    #[inline]
    fn from(from: [u8; PUBKEY_BYTES]) -> Self {
        Self(from)
    }
}

impl TryFrom<&[u8]> for Pubkey {
    type Error = std::array::TryFromSliceError;

    #[inline]
    fn try_from(pubkey: &[u8]) -> Result<Self, Self::Error> {
        <[u8; PUBKEY_BYTES]>::try_from(pubkey).map(Self::from)
    }
}

impl TryFrom<Vec<u8>> for Pubkey {
    type Error = Vec<u8>;

    #[inline]
    fn try_from(pubkey: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; PUBKEY_BYTES]>::try_from(pubkey).map(Self::from)
    }
}

impl TryFrom<&str> for Pubkey {
    type Error = ParsePubkeyError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Pubkey::from_str(s)
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl AsRef<[u8]> for Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Pubkey {
    pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
        Self::try_find_program_address(seeds, program_id)
            .unwrap_or_else(|| panic!("Unable to find a viable program address bump seed"))
    }

    pub fn try_find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
        {
            let mut bump_seed = [u8::MAX];
            for _ in 0..u8::MAX {
                {
                    let mut seeds_with_bump = seeds.to_vec();
                    seeds_with_bump.push(&bump_seed);
                    match Self::create_program_address(&seeds_with_bump, program_id) {
                        Ok(address) => return Some((address, bump_seed[0])),
                        Err(PubkeyError::InvalidSeeds) => (),
                        _ => break,
                    }
                }
                bump_seed[0] -= 1;
            }
            None
        }
    }

    pub fn create_program_address(
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<Pubkey, PubkeyError> {
        if seeds.len() > MAX_SEEDS {
            return Err(PubkeyError::MaxSeedLengthExceeded);
        }
        for seed in seeds.iter() {
            if seed.len() > MAX_SEED_LEN {
                return Err(PubkeyError::MaxSeedLengthExceeded);
            }
        }

        {
            let mut hasher = crate::types::hash::Hasher::default();
            for seed in seeds.iter() {
                hasher.hash(seed);
            }
            hasher.hashv(&[program_id.as_ref(), PDA_MARKER]);
            let hash = hasher.result();

            if bytes_are_curve_point(hash) {
                return Err(PubkeyError::InvalidSeeds);
            }

            Ok(Pubkey::from(hash.to_bytes()))
        }
    }
}

#[derive(Error, Debug, Serialize, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    /// Length of the seed is too long for address generation
    #[error("Length of the seed is too long for address generation")]
    MaxSeedLengthExceeded,
    #[error("Provided seeds do not result in a valid address")]
    InvalidSeeds,
    #[error("Provided owner is not allowed")]
    IllegalOwner,
}

#[allow(clippy::used_underscore_binding)]
pub fn bytes_are_curve_point<T: AsRef<[u8]>>(_bytes: T) -> bool {
    #[cfg(not(target_os = "solana"))]
    {
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(_bytes.as_ref())
            .decompress()
            .is_some()
    }
    #[cfg(target_os = "solana")]
    unimplemented!();
}
