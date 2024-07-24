use sha2::{Digest, Sha256};
use std::fmt;

pub const HASH_BYTES: usize = 32;

#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash(pub(crate) [u8; HASH_BYTES]);

#[derive(Clone, Default)]
pub struct Hasher {
    hasher: Sha256,
}

impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
        self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
        for val in vals {
            self.hash(val);
        }
    }
    pub fn result(self) -> Hash {
        Hash(self.hasher.finalize().into())
    }
}

impl From<[u8; HASH_BYTES]> for Hash {
    fn from(from: [u8; 32]) -> Self {
        Self(from)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl Hash {
    pub fn to_bytes(self) -> [u8; HASH_BYTES] {
        self.0
    }
}
