use crate::constants::{NODES_IN_FIDUCIARY_SUBNET, SCHNORR_KEY_NAME};
use candid::{CandidType, Deserialize};
use ic_solana::types::Cluster;
use serde::Serialize;
use std::cell::RefCell;

thread_local! {
    pub static STATE: RefCell<Option<State>> = RefCell::default();
}

/// Solana RPC canister initialization data.
#[derive(Debug, Deserialize, CandidType, Clone)]
pub struct InitArgs {
    pub rpc_url: Option<String>,
    pub nodes_in_subnet: Option<u32>,
    pub schnorr_key_name: Option<String>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct State {
    pub rpc_url: String,
    pub schnorr_key_name: String,
    pub nodes_in_subnet: u32,
}

impl From<InitArgs> for State {
    fn from(value: InitArgs) -> Self {
        Self {
            rpc_url: value.rpc_url.unwrap_or(Cluster::Devnet.to_string()),

            schnorr_key_name: value
                .schnorr_key_name
                .unwrap_or(SCHNORR_KEY_NAME.to_string()),
            nodes_in_subnet: value.nodes_in_subnet.unwrap_or(NODES_IN_FIDUCIARY_SUBNET),
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Solana RPC URL: {:?}", self.rpc_url)?;

        writeln!(f, "Schnorr key name: {:?}", self.schnorr_key_name)?;
        writeln!(f, "Nodes in subnet: {:?}", self.nodes_in_subnet)?;
        Ok(())
    }
}

/// Take the current state.
///
/// After calling this function, the state won't be initialized anymore.
/// Panics if there is no state.
pub fn take_state<F, R>(f: F) -> R
where
    F: FnOnce(State) -> R,
{
    STATE.with(|s| f(s.take().expect("State not initialized!")))
}

/// Read (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("State not initialized!")))
}

pub fn replace_state(state: State) {
    STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| f(s.borrow_mut().as_mut().expect("State not initialized!")))
}
