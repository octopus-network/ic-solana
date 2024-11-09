use crate::token::constants::compute_budget_id;
use crate::types::Instruction;
// use borsh::{BorshDeserialize, BorshSerialize};
use anyhow::anyhow;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use candid::CandidType;
use core::fmt;
use serde_derive::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};
// const DEFAULT_SERIALIZER_CAPACITY: usize = 1024;

// Temporary values--calculate this properly later.
pub const DEFAULT_COMPUTE_UNITS: u64 = 200_000;
pub const UPDATE_COMPUTE_UNITS: u32 = 50_000;

// Temporary simple priority fees
#[derive(CandidType, Deserialize, Serialize, Debug, Default, Clone, Eq, PartialEq)]
pub enum Priority {
    #[default]
    None,
    Low,
    Medium,
    High,
    Max,
}

impl FromStr for Priority {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "max" => Ok(Self::Max),
            _ => Err(anyhow!("Invalid priority".to_string())),
        }
    }
}

impl Display for Priority {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Max => write!(f, "Max"),
        }
    }
}

/// Compute Budget Instructions
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ComputeBudgetInstruction {
    /// Deprecated
    // TODO: after feature remove_deprecated_request_unit_ix::id() is activated, replace it with 'unused'
    RequestUnitsDeprecated {
        /// Units to request
        units: u32,
        /// Additional fee to add
        additional_fee: u32,
    },
    /// Request a specific transaction-wide program heap region size in bytes.
    /// The value requested must be a multiple of 1024. This new heap region
    /// size applies to each program executed in the transaction, including all
    /// calls to CPIs.
    RequestHeapFrame(u32),
    /// Set a specific compute unit limit that the transaction is allowed to consume.
    SetComputeUnitLimit(u32),
    /// Set a compute unit price in "micro-lamports" to pay a higher transaction
    /// fee for higher transaction prioritization.
    SetComputeUnitPrice(u64),
    /// Set a specific transaction-wide account data size limit, in bytes, is allowed to load.
    SetLoadedAccountsDataSizeLimit(u32),
}

impl ComputeBudgetInstruction {
    /// Create a `ComputeBudgetInstruction::RequestHeapFrame` `Instruction`
    pub fn request_heap_frame(bytes: u32) -> Instruction {
        Instruction::new_with_borsh(compute_budget_id(), &Self::RequestHeapFrame(bytes), vec![])
    }

    /// Create a `ComputeBudgetInstruction::SetComputeUnitLimit` `Instruction`
    pub fn set_compute_unit_limit(units: u32) -> Instruction {
        Instruction::new_with_borsh(
            compute_budget_id(),
            &Self::SetComputeUnitLimit(units),
            vec![],
        )
    }

    /// Create a `ComputeBudgetInstruction::SetComputeUnitPrice` `Instruction`
    pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
        Instruction::new_with_borsh(
            compute_budget_id(),
            &Self::SetComputeUnitPrice(micro_lamports),
            vec![],
        )
    }

    /// Serialize Instruction using borsh, this is only used in runtime::cost_model::tests but compilation
    /// can't be restricted as it's used across packages
    // #[cfg(test)]
    pub fn pack(self) -> Result<Vec<u8>, std::io::Error> {
        // self.try_to_vec()
        // let mut result = Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY);
        // self.serialize(&mut result)?;
        borsh::to_vec(&self)
        // Ok(result)
    }

    /// Create a `ComputeBudgetInstruction::SetLoadedAccountsDataSizeLimit` `Instruction`
    pub fn set_loaded_accounts_data_size_limit(bytes: u32) -> Instruction {
        Instruction::new_with_borsh(
            compute_budget_id(),
            &Self::SetLoadedAccountsDataSizeLimit(bytes),
            vec![],
        )
    }
}
