use candid::Deserialize;

use crate::state::State;
use serde::Serialize;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PreState {
    pub rpc_url: String,
    pub schnorr_canister: String,
    pub schnorr_key_name: String,
    pub nodes_in_subnet: u32,
}

pub fn _migrate(pre_state: PreState) -> State {
    let new_state = State {
        rpc_url: pre_state.rpc_url,
        schnorr_key_name: pre_state.schnorr_key_name,
        nodes_in_subnet: pre_state.nodes_in_subnet,
        enable_debug: false,
    };

    new_state
}
