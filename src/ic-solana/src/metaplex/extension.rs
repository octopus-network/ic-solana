use crate::token::program_error::ProgramError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// Extensions that can be applied to mints or accounts.  Mint extensions must
/// only be applied to mint accounts, and account extensions must only be
/// applied to token holding accounts.
#[repr(u16)]
#[derive(
    Clone, Copy, Debug, PartialEq, TryFromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum ExtensionType {
    /// Used as padding if the account size would otherwise be 355, same as a
    /// multisig
    Uninitialized,
    /// Includes transfer fee rate info and accompanying authorities to withdraw
    /// and set the fee
    TransferFeeConfig,
    /// Includes withheld transfer fees
    TransferFeeAmount,
    /// Includes an optional mint close authority
    MintCloseAuthority,
    /// Auditor configuration for confidential transfers
    ConfidentialTransferMint,
    /// State for confidential transfers
    ConfidentialTransferAccount,
    /// Specifies the default Account::state for new Accounts
    DefaultAccountState,
    /// Indicates that the Account owner authority cannot be changed
    ImmutableOwner,
    /// Require inbound transfers to have memo
    MemoTransfer,
    /// Indicates that the tokens from this mint can't be transferred
    NonTransferable,
    /// Tokens accrue interest over time,
    InterestBearingConfig,
    /// Locks privileged token operations from happening via CPI
    CpiGuard,
    /// Includes an optional permanent delegate
    PermanentDelegate,
    /// Indicates that the tokens in this account belong to a non-transferable
    /// mint
    NonTransferableAccount,
    /// Mint requires a CPI to a program implementing the "transfer hook"
    /// interface
    TransferHook,
    /// Indicates that the tokens in this account belong to a mint with a
    /// transfer hook
    TransferHookAccount,
    /// Includes encrypted withheld fees and the encryption public that they are
    /// encrypted under
    ConfidentialTransferFeeConfig,
    /// Includes confidential withheld transfer fees
    ConfidentialTransferFeeAmount,
    /// Mint contains a pointer to another account (or the same account) that
    /// holds metadata
    MetadataPointer,
    /// Mint contains token-metadata
    TokenMetadata,
    /// Mint contains a pointer to another account (or the same account) that
    /// holds group configurations
    GroupPointer,
    /// Mint contains token group configurations
    TokenGroup,
    /// Mint contains a pointer to another account (or the same account) that
    /// holds group member configurations
    GroupMemberPointer,
    /// Mint contains token group member configurations
    TokenGroupMember,
    /// Test variable-length mint extension
    #[cfg(test)]
    VariableLenMintTest = u16::MAX - 2,
    /// Padding extension used to make an account exactly Multisig::LEN, used
    /// for testing
    #[cfg(test)]
    AccountPaddingTest,
    /// Padding extension used to make a mint exactly Multisig::LEN, used for
    /// testing
    #[cfg(test)]
    MintPaddingTest,
}
impl TryFrom<&[u8]> for ExtensionType {
    type Error = ProgramError;
    fn try_from(a: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(u16::from_le_bytes(
            a.try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        ))
        .map_err(|_| ProgramError::InvalidAccountData)
    }
}
impl From<ExtensionType> for [u8; 2] {
    fn from(a: ExtensionType) -> Self {
        u16::from(a).to_le_bytes()
    }
}
