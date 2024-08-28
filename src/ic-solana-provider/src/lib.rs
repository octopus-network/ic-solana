use crate::types::SendTransactionRequest;
use crate::utils::{rpc_client, validate_caller_not_anonymous};
use eddsa_api::{eddsa_public_key, sign_with_eddsa};
use ic_canister_log::export as export_logs;
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse as TransformedHttpResponse,
    TransformArgs,
};
use ic_cdk::{query, update};
use ic_solana::http_request_required_cycles;
use ic_solana::logs::DEBUG;
use ic_solana::response::{OptionalContext, Response, RpcBlockhash};
use ic_solana::rpc_client::{JsonRpcResponse, RpcResult};
use ic_solana::types::{
    BlockHash, EncodingConfig, Instruction, Message, Pubkey, RpcAccountInfoConfig,
    RpcContextConfig, RpcSendTransactionConfig, RpcSignatureStatusConfig, RpcTransactionConfig,
    Signature, Transaction, TransactionStatus, UiAccount, UiAccountEncoding, UiTokenAmount,
    UiTransactionEncoding,
};
use ic_stable_structures::writer::Writer;
use ic_stable_structures::Memory;
// use migration::{migrate, PreState};
use candid::Nat;
use serde_bytes::ByteBuf;
use serde_json::{from_str, json, Value};
use state::{mutate_state, read_state, replace_state, InitArgs, State, STATE};
use std::str::FromStr;
mod constants;
pub mod eddsa_api;
mod memory;
mod migration;
pub mod state;
pub mod types;
mod utils;

///
/// Returns the public key of the Solana wallet for the caller.
///
#[update]
pub async fn get_address() -> String {
    let caller = validate_caller_not_anonymous();
    let key_name = read_state(|s| s.schnorr_key_name.clone());
    let derived_path = vec![ByteBuf::from(caller.as_slice())];
    let pk = eddsa_public_key(key_name, derived_path).await;
    Pubkey::try_from(pk.as_slice())
        .expect("Invalid public key")
        .to_string()
}

///
/// Calls a JSON-RPC method on a Solana node at the specified URL.
///
#[update]
pub async fn request(method: String, params: String, max_response_bytes: u64) -> RpcResult<String> {
    let client = rpc_client();
    let parsed_params: Value = from_str(&params).expect("Failed to parse JSON");
    let payload = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": client.next_request_id(),
        "method": &method,
        "params": parsed_params
    }))?;
    client.call(&payload, max_response_bytes, None).await
}

///
/// Calculates the cost of an RPC request.
///
#[query(name = "requestCost")]
pub fn request_cost(payload: String, max_response_bytes: u64) -> u128 {
    let client = rpc_client();

    let request = CanisterHttpRequestArgument {
        url: client.cluster.url().to_string(),
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::POST,
        headers: vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: Some(payload.as_bytes().to_vec()),
        transform: None,
    };

    http_request_required_cycles(&request, read_state(|s| s.nodes_in_subnet))
}

///
/// Returns the lamport balance of the account of provided Pubkey.
///
#[update(name = "sol_getBalance")]
pub async fn sol_get_balance(pubkey: String) -> RpcResult<u64> {
    let client = rpc_client();
    let balance = client
        .get_balance(
            &Pubkey::from_str(&pubkey).expect("Invalid public key"),
            RpcContextConfig::default(),
        )
        .await?;
    Ok(balance)
}

///
/// Returns minimum balance required to make account rent exempt.
///
#[update(name = "sol_getminimumbalanceforrentexemption")]
pub async fn sol_get_minimum_balance_for_rent_exemption(data_len: usize) -> RpcResult<u64> {
    let client = rpc_client();
    let balance = client
        .get_minimum_balance_for_rent_exemption(data_len)
        .await?;
    Ok(balance)
}

///
/// Returns the token balance of an SPL Token account.
///
#[update(name = "sol_getTokenBalance")]
pub async fn sol_get_token_balance(pubkey: String) -> RpcResult<UiTokenAmount> {
    let client = rpc_client();
    let commitment = None;
    let balance = client
        .get_token_account_balance(
            &Pubkey::from_str(&pubkey).expect("Invalid public key"),
            commitment,
        )
        .await?;
    Ok(balance)
}

///
/// Returns the latest blockhash.
///
#[update(name = "sol_latestBlockhash")]
pub async fn sol_get_latest_blockhash() -> RpcResult<String> {
    let client = rpc_client();
    let blockhash = client
        .get_latest_blockhash(RpcContextConfig::default())
        .await?;
    Ok(blockhash.to_string())
}
#[query(hidden = true)]
fn transform_blockhash(mut args: TransformArgs) -> TransformedHttpResponse {
    log!(
        DEBUG,
        "[ic-solana-provider] transform_blockhash TransformArgs: {:?}",
        args
    );

    args.response.headers.clear();
    let block_hash_body = String::from_utf8(args.response.body.clone()).unwrap();
    let json_response =
        serde_json::from_str::<JsonRpcResponse<OptionalContext<RpcBlockhash>>>(&block_hash_body)
            .unwrap();
    log!(
        DEBUG,
        "[ic-solana-provider] transform_blockhash json_response : {:?}",
        json_response
    );
    if let Some(e) = json_response.error {
        log!(
            DEBUG,
            "[ic-solana-provider] transform_blockhash response error: {:?}",
            e
        );

        return args.response;
    }
    if json_response.result.is_none() {
        log!(
            DEBUG,
            "[ic-solana-provider] transform_blockhash json_response.result is none !",
        );
        return args.response;
    }
    let account_resp = json_response.result.unwrap();
    let result = match account_resp {
        OptionalContext::NoContext(value) => OptionalContext::NoContext(value),
        OptionalContext::Context(mut ctx) => {
            // reset slot to 0
            ctx.context.slot = 0;
            log!(
                DEBUG,
                "[ic-solana-provider] transform_blockhash reset slot to 0 : {:?}",
                ctx
            );
            OptionalContext::Context(ctx)
        }
    };

    let new_json_rpc_resp = JsonRpcResponse {
        jsonrpc: json_response.jsonrpc,
        result: Some(result),
        error: json_response.error,
        id: json_response.id,
    };
    let new_body = serde_json::to_string(&new_json_rpc_resp).unwrap();

    let resp = TransformedHttpResponse {
        status: args.response.status,
        headers: vec![],
        body: new_body.into_bytes(),
    };
    log!(
        DEBUG,
        "[ic-solana-provider] transform_blockhash transformed response: {:?}",
        resp
    );
    resp
}
///
/// Returns all information associated with the account of provided Pubkey.
///
#[update(name = "sol_getAccountInfo")]
pub async fn sol_get_account_info(pubkey: String) -> RpcResult<Option<String>> {
    let client = rpc_client();
    let account_info = client
        .get_account_info1(
            &Pubkey::from_str(&pubkey).expect("Invalid public key"),
            RpcAccountInfoConfig {
                // Encoded binary (base58) data should be less than 128 bytes, so use base64 encoding.
                encoding: Some(UiAccountEncoding::Base64),
                data_slice: None,
                commitment: None,
                min_context_slot: None,
            },
            None,
        )
        .await?;
    Ok(account_info)
}

#[query(hidden = true)]
fn transform_account(mut args: TransformArgs) -> TransformedHttpResponse {
    log!(
        DEBUG,
        "[ic-solana-provider] transform_account TransformArgs: {:?}",
        args
    );
    args.response.headers.clear();
    let block_hash_body = String::from_utf8(args.response.body.clone()).unwrap();
    let json_response =
        serde_json::from_str::<JsonRpcResponse<Response<Option<UiAccount>>>>(&block_hash_body)
            .unwrap();
    log!(
        DEBUG,
        "[ic-solana-provider] transform_account json_response : {:?}",
        json_response
    );
    if let Some(e) = json_response.error {
        log!(
            DEBUG,
            "[ic-solana-provider] transform_account response error: {:?}",
            e
        );

        return args.response;
    }
    if json_response.result.is_none() {
        log!(
            DEBUG,
            "[ic-solana-provider] transform_account json_response.result is none !",
        );
        return args.response;
    }
    let mut account_resp = json_response.result.unwrap();
    // reset slot to 0
    account_resp.context.slot = 0;
    log!(
        DEBUG,
        "[ic-solana-provider] transform_account reset slot to 0 : {:?}",
        account_resp
    );
    let new_json_rpc_resp = JsonRpcResponse {
        jsonrpc: json_response.jsonrpc,
        result: Some(account_resp),
        error: json_response.error,
        id: json_response.id,
    };
    let new_body = serde_json::to_string(&new_json_rpc_resp).unwrap();

    let resp = TransformedHttpResponse {
        status: args.response.status,
        headers: vec![],
        body: new_body.into_bytes(),
    };
    log!(
        DEBUG,
        "[ic-solana-provider] transform_account transformed response: {:?}",
        resp
    );
    resp
}

///
/// Returns transaction details for a confirmed transaction.
///
#[update(name = "sol_getTransaction")]
pub async fn sol_get_transaction(signature: String) -> RpcResult<String> {
    let client = rpc_client();
    let signature = Signature::from_str(&signature).expect("Invalid signature");
    let response = client
        .get_transaction1(
            &signature,
            RpcTransactionConfig::new_with_encoding(&Some(UiTransactionEncoding::JsonParsed)),
        )
        .await?;
    Ok(response)
}

///
/// Returns the statuses of a list of transaction signatures.
///
#[update(name = "sol_getSignatureStatuses")]
pub async fn sol_get_signature_statuses(signatures: Vec<String>) -> RpcResult<String> {
    let client = rpc_client();

    let signatures = signatures
        .iter()
        .map(|s| Signature::from_str(s).unwrap())
        .collect::<Vec<_>>();

    let response = client
        .get_signature_statuses(
            &signatures,
            RpcSignatureStatusConfig {
                search_transaction_history: true,
            },
        )
        .await?;
    log!(
        DEBUG,
        "[ic-solana-provider] sol_get_signature_statuses response: {:?}",
        response
    );
    let response_str = serde_json::to_string(&response).unwrap();
    log!(
        DEBUG,
        "[ic-solana-provider] sol_get_signature_statuses response_str: {:?}",
        response_str
    );
    Ok(response_str)
}

#[query(hidden = true)]
fn transform_signature_statuses(mut args: TransformArgs) -> TransformedHttpResponse {
    log!(
        DEBUG,
        "[ic-solana-provider] transform_signature_statuses TransformArgs: {:?}",
        args
    );
    args.response.headers.clear();
    let block_hash_body = String::from_utf8(args.response.body.clone()).unwrap();
    let json_response = serde_json::from_str::<
        JsonRpcResponse<Response<Option<Vec<TransactionStatus>>>>,
    >(&block_hash_body)
    .unwrap();
    log!(
        DEBUG,
        "[ic-solana-provider] transform_signature_statuses json_response : {:?}",
        json_response
    );
    if let Some(e) = json_response.error {
        log!(
            DEBUG,
            "[ic-solana-provider] transform_signature_statuses response error: {:?}",
            e
        );

        return args.response;
    }
    if json_response.result.is_none() {
        log!(
            DEBUG,
            "[ic-solana-provider] transform_signature_statuses json_response.result is none !",
        );
        return args.response;
    }
    let mut account_resp = json_response.result.unwrap();
    // reset slot to 0
    account_resp.context.slot = 0;
    log!(
        DEBUG,
        "[ic-solana-provider] transform_signature_statuses reset slot to 0 : {:?}",
        account_resp
    );
    let new_json_rpc_resp = JsonRpcResponse {
        jsonrpc: json_response.jsonrpc,
        result: Some(account_resp),
        error: json_response.error,
        id: json_response.id,
    };
    let new_body = serde_json::to_string(&new_json_rpc_resp).unwrap();

    let resp = TransformedHttpResponse {
        status: args.response.status,
        headers: vec![],
        body: new_body.into_bytes(),
    };
    log!(
        DEBUG,
        "[ic-solana-provider] transform_signature_statuses transformed response: {:?}",
        resp
    );
    resp
}

///
/// Send a transaction to the network.
///
#[update(name = "sol_sendTransaction")]
pub async fn sol_send_transaction(req: SendTransactionRequest) -> RpcResult<String> {
    let caller = validate_caller_not_anonymous();
    let client = rpc_client();

    let recent_blockhash = match req.recent_blockhash {
        Some(r) => BlockHash::from_str(&r).expect("Invalid recent blockhash"),
        None => {
            client
                .get_latest_blockhash(RpcContextConfig::default())
                .await?
        }
    };

    let ixs = &req
        .instructions
        .iter()
        .map(|s| Instruction::from_str(s).unwrap())
        .collect::<Vec<_>>();

    let message = Message::new_with_blockhash(ixs, None, &recent_blockhash);

    let mut tx = Transaction::new_unsigned(message);

    let key_name = read_state(|s| s.schnorr_key_name.clone());
    let derived_path = vec![ByteBuf::from(caller.as_slice())];

    let signature = sign_with_eddsa(key_name, derived_path, tx.message_data())
        .await
        .try_into()
        .expect("Invalid signature");

    tx.add_signature(0, signature);

    let signature = client
        .send_transaction(tx, RpcSendTransactionConfig::default())
        .await?;

    Ok(signature.to_string())
}

///
/// Submits a signed transaction to the cluster for processing.
///
#[update(name = "sol_sendRawTransaction")]
pub async fn send_raw_transaction(raw_signed_transaction: String) -> RpcResult<String> {
    log!(
        DEBUG,
        "[ic-solana-provider] send_raw_transaction raw_signed_transaction: {:?}",
        raw_signed_transaction
    );

    let client = rpc_client();

    let tx = Transaction::from_str(&raw_signed_transaction).expect("Invalid transaction");

    let signature = client
        .send_transaction(tx, RpcSendTransactionConfig::default())
        .await?;

    Ok(signature.to_string())
}

/// Cleans up the HTTP response headers to make them deterministic.
///
/// # Arguments
///
/// * `args` - Transformation arguments containing the HTTP response.
///
#[query(hidden = true)]
fn cleanup_response(mut args: TransformArgs) -> TransformedHttpResponse {
    // The response header contains non-deterministic fields that make it impossible to reach consensus!
    // Errors seem deterministic and do not contain data that can break consensus.
    // Clear non-deterministic fields from the response headers.

    log!(
        DEBUG,
        "[ic-solana-provider] cleanup_response TransformArgs: {:?}",
        args
    );
    args.response.headers.clear();
    args.response
}

#[query(hidden = true)]
fn transform_tx_response(mut args: TransformArgs) -> TransformedHttpResponse {
    log!(
        DEBUG,
        "[ic-solana-provider] transform_tx_response TransformArgs: {:?}",
        args
    );
    args.response.headers.clear();
    args.response.status = Nat::from(200u32);
    args.response.body = args.context;

    log!(
        DEBUG,
        "[ic-solana-provider] transform_tx_response transformed response: {:?}",
        args.response
    );
    args.response
}

#[query]
fn get_responses() -> Vec<(u64, TransformedHttpResponse)> {
    read_state(|s| {
        s.responses
            .iter()
            .map(|(timestamp, resp)| (timestamp.to_owned(), resp.to_owned()))
            .collect::<Vec<_>>()
    })
}

#[query(hidden = true)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }

    if req.path() == "/logs" {
        use serde_json;
        use std::str::FromStr;

        let max_skip_timestamp = match req.raw_query_param("time") {
            Some(arg) => match u64::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'time' parameter")
                        .build()
                }
            },
            None => 0,
        };

        let mut entries = vec![];
        for entry in export_logs(&ic_solana::logs::ERROR_BUF) {
            entries.push(entry);
        }
        for entry in export_logs(&ic_solana::logs::DEBUG_BUF) {
            entries.push(entry);
        }
        entries.retain(|entry| entry.timestamp >= max_skip_timestamp);
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    STATE.with(|s| {
        *s.borrow_mut() = Some(args.into());
    });
}

#[ic_cdk::pre_upgrade]
pub fn pre_upgrade() {
    // Serialize the state.
    let mut state_bytes = vec![];
    let _ = read_state(|s| ciborium::ser::into_writer(&s, &mut state_bytes));
    // Write the length of the serialized bytes to memory, followed by the
    // by the bytes themselves.
    let len = state_bytes.len() as u32;
    let mut memory = memory::get_upgrades_memory();
    let mut writer = Writer::new(&mut memory, 0);
    writer
        .write(&len.to_le_bytes())
        .expect("failed to save hub state len");
    writer
        .write(&state_bytes)
        .expect("failed to save hub state");
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: InitArgs) {
    let memory = memory::get_upgrades_memory();
    // Read the length of the state bytes.
    let mut state_len_bytes = [0; 4];
    memory.read(0, &mut state_len_bytes);
    let state_len = u32::from_le_bytes(state_len_bytes) as usize;

    // Read the bytes
    let mut state_bytes = vec![0; state_len];
    memory.read(4, &mut state_bytes);

    // Deserialize pre state
    let pre_state: State =
        ciborium::de::from_reader(&*state_bytes).expect("failed to decode state");
    // let new_state = migrate(pre_state);
    replace_state(pre_state);

    // update args
    if let Some(v) = args.rpc_url {
        mutate_state(|s| s.rpc_url = v);
    }
    if let Some(v) = args.nodes_in_subnet {
        mutate_state(|s| s.nodes_in_subnet = v);
    }
    if let Some(v) = args.schnorr_canister {
        mutate_state(|s| s.schnorr_canister = v);
    }
    if let Some(v) = args.schnorr_key_name {
        mutate_state(|s| s.schnorr_key_name = v);
    }
    log!(DEBUG, "[ic-solana-provider] upgrade successfully!");
}

ic_cdk::export_candid!();
