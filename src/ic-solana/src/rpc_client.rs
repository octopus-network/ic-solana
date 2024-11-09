use crate::constants::*;
use crate::eddsa::hash_with_sha256;
use crate::ic_log::{DEBUG, ERROR};
use crate::request::RpcRequest;
use crate::response::{
    EncodedConfirmedBlock, OptionalContext, Response, RpcBlockhash,
    RpcConfirmedTransactionStatusWithSignature, RpcKeyedAccount, RpcSimulateTransactionResult,
    RpcSupply, RpcVersionInfo,
};
use crate::types::{
    Account, BlockHash, CommitmentConfig, RpcSimulateTransactionConfig, RpcTransactionConfig, Slot,
    UiAccount, UiTokenAmount,
};
use crate::types::{
    Cluster, EncodedConfirmedTransactionWithStatusMeta, EpochInfo, Pubkey, RpcAccountInfoConfig,
    RpcContextConfig, RpcProgramAccountsConfig, RpcSendTransactionConfig, RpcSignatureStatusConfig,
    RpcSignaturesForAddressConfig, RpcSupplyConfig, Signature, Transaction, TransactionStatus,
    UiTransactionEncoding,
};
use crate::utils::get_http_request_cost;
use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use candid::CandidType;
use ic_canister_log::log;
use ic_cdk::api;
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::str::FromStr;

thread_local! {
    static NEXT_ID: RefCell<u64> = RefCell::default();
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub result: Option<T>,
    pub error: Option<JsonRpcError>,
    pub id: u64,
}

#[derive(Debug, thiserror::Error, Deserialize, CandidType)]
pub enum RpcError {
    #[error("RPC request error: {0}")]
    RpcRequestError(String),
    #[error("RPC response error {code}: {message} {data:?}")]
    RpcResponseError {
        code: i64,
        message: String,
        data: Option<String>,
    },
    #[error("parse error: expected {0}")]
    ParseError(String),
    #[error("{0}")]
    Text(String),
}

impl From<JsonRpcError> for RpcError {
    fn from(e: JsonRpcError) -> Self {
        Self::RpcResponseError {
            code: e.code,
            message: e.message,
            data: None,
        }
    }
}

impl From<serde_json::Error> for RpcError {
    fn from(e: serde_json::Error) -> Self {
        let error_string = e.to_string();
        Self::ParseError(error_string)
    }
}

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcClient {
    pub cluster: Cluster,
    pub commitment_config: CommitmentConfig,
    pub nodes_in_subnet: Option<u32>,
}

impl RpcClient {
    pub fn new(cluster: &str) -> Self {
        Self {
            cluster: Cluster::from_str(cluster).unwrap(),
            commitment_config: CommitmentConfig::confirmed(),
            nodes_in_subnet: None,
        }
    }

    pub fn with_commitment(mut self, commitment_config: CommitmentConfig) -> Self {
        self.commitment_config = commitment_config;
        self
    }

    pub fn with_nodes_in_subnet(mut self, nodes_in_subnet: u32) -> Self {
        self.nodes_in_subnet = Some(nodes_in_subnet);
        self
    }

    /// Asynchronously sends an HTTP POST request to the specified URL with the given payload and
    /// maximum response bytes, and returns the response as a string.
    /// This function calculates the required cycles for the HTTP request and logs the request
    /// details and response status. It uses a transformation named "cleanup_response" for the
    /// response body.
    ///
    /// # Arguments
    ///
    /// * `payload` - A string slice that holds the JSON payload to be sent in the HTTP request.
    /// * `max_response_bytes` - A u64 value representing the maximum number of bytes for the response.
    ///
    /// # Returns
    ///
    /// * `RpcResult<String>` - A result type that contains the response body as a string if the request
    /// is successful, or an `RpcError` if the request fails.
    ///
    /// # Errors
    ///
    /// This function returns an `RpcError` in the following cases:
    /// * If the response body cannot be parsed as a UTF-8 string, a `ParseError` is returned.
    /// * If the HTTP request fails, an `RpcRequestError` is returned with the error details.
    ///
    pub async fn call(
        &self,
        forward: Option<String>,
        payload: &str,
        max_response_bytes: u64,
        transform: Option<TransformContext>,
    ) -> RpcResult<String> {
        let transform = transform.unwrap_or(TransformContext::from_name(
            "cleanup_response".to_owned(),
            vec![],
        ));

        let mut headers = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }];
        // add idempotency_key
        let idempotency_key = hash_with_sha256(payload);

        headers.push(HttpHeader {
            name: "X-Idempotency".to_string(),
            value: idempotency_key,
        });
        // add forward address
        if let Some(forward) = forward {
            headers.push(HttpHeader {
                name: "X-Forward-Solana".to_string(),
                value: forward,
            });
        }
        // add sol.nownodes.io key
        // headers.push(HttpHeader {
        //     name: "api-key".to_string(),
        //     value: "c358082d-9e68-43da-a0fb-6f7240d01136".to_string(),
        // });

        log!(
            DEBUG,
            "ic-solana::rpc_client::call: http header: {:?}",
            headers
        );

        let request = CanisterHttpRequestArgument {
            url: self.cluster.url().to_string(),
            max_response_bytes: Some(max_response_bytes + HEADER_SIZE_LIMIT),
            // max_response_bytes: None,
            method: HttpMethod::POST,
            headers: headers,
            body: Some(payload.as_bytes().to_vec()),
            transform: Some(transform),
        };

        let url = self.cluster.url();
        // let nodes_in_standard_subnet = 13;

        // let cycles = http_request_required_cycles(
        //     &request,
        //     self.nodes_in_subnet.unwrap_or(nodes_in_standard_subnet),
        // );

        let cycles = get_http_request_cost(
            request.body.as_ref().map_or(0, |b| b.len() as u64),
            request.max_response_bytes.unwrap_or(2 * 1024 * 1024), // default 2Mb
        );

        log!(
            DEBUG,
            "Calling url: {url} with payload: {payload}. Cycles: {cycles}"
        );
        let start = api::time();
        match http_request(request, cycles).await {
            Ok((response,)) => {
                let end = api::time();
                let elapsed = (end - start) / 1_000_000_000;

                log!(
                    DEBUG,
                    "Got response (with {} bytes): {} from url: {} with status: {} the time elapsed: {}",
                    response.body.len(),
                    String::from_utf8_lossy(&response.body),
                    url,
                    response.status,
                    elapsed
                );

                match String::from_utf8(response.body) {
                    Ok(body) => Ok(body),
                    Err(error) => Err(RpcError::ParseError(error.to_string())),
                }
            }
            Err((r, m)) => {
                let end = api::time();
                let elapsed = (end - start) / 1_000_000_000;
                log!(
                    ERROR,
                    "Got response  error : {:?},{} from url: {} ,the time elapsed: {}",
                    r,
                    m,
                    url,
                    elapsed
                );
                Err(RpcError::RpcRequestError(format!("({r:?}) {m:?}")))
            }
        }
    }

    pub fn next_request_id(&self) -> u64 {
        NEXT_ID.with(|next_id| {
            let mut next_id = next_id.borrow_mut();
            let id = *next_id;
            *next_id = next_id.wrapping_add(1);
            id
        })
    }

    ///
    /// Returns the latest blockhash.
    ///
    /// Method relies on the `getLatestBlockhash` RPC call to get the latest blockhash:
    ///   https://solana.com/docs/rpc/http/getLatestBlockhash
    ///
    pub async fn get_latest_blockhash(
        &self,
        config: RpcContextConfig,
        forward: Option<String>,
    ) -> RpcResult<BlockHash> {
        let payload = RpcRequest::GetLatestBlockhash
            .build_request_json(self.next_request_id(), json!([config]))
            .to_string();
        let transform = TransformContext::from_name("transform_blockhash".to_owned(), vec![]);
        let response = self.call(forward, &payload, 156, Some(transform)).await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<OptionalContext<RpcBlockhash>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            let RpcBlockhash {
                blockhash,
                last_valid_block_height: _,
            } = json_response.result.unwrap().parse_value();

            let blockhash = blockhash
                .parse()
                .map_err(|_| RpcError::ParseError("BlockHash".to_string()))?;

            Ok(blockhash)
        }
    }

    ///
    /// Returns the lamport balance of the account of provided Pubkey.
    ///
    /// Method relies on the `getBalance` RPC call to get the balance:
    ///   https://solana.com/docs/rpc/http/getBalance
    ///
    pub async fn get_balance(
        &self,
        pubkey: &Pubkey,
        config: RpcContextConfig,
        forward: Option<String>,
    ) -> RpcResult<u64> {
        let payload = RpcRequest::GetBalance
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]))
            .to_string();

        let response = self.call(forward, &payload, 156, None).await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<OptionalContext<u64>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns the token balance of an SPL Token account.
    ///
    /// Method relies on the `getTokenAccountBalance` RPC call to get the token balance:
    ///   https://solana.com/docs/rpc/http/getTokenAccountBalance
    ///
    pub async fn get_token_account_balance(
        &self,
        pubkey: &Pubkey,
        commitment: Option<CommitmentConfig>,
        forward: Option<String>,
    ) -> RpcResult<UiTokenAmount> {
        let payload = RpcRequest::GetTokenAccountBalance
            .build_request_json(
                self.next_request_id(),
                json!([pubkey.to_string(), commitment]),
            )
            .to_string();

        let response = self.call(forward, &payload, 256, None).await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<OptionalContext<UiTokenAmount>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns all information associated with the account of provided Pubkey.
    ///
    /// Method relies on the `getAccountInfo` RPC call to get the account info:
    ///   https://solana.com/docs/rpc/http/getAccountInfo
    ///
    pub async fn get_account_info(
        &self,
        pubkey: &Pubkey,
        config: RpcAccountInfoConfig,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<Option<Account>> {
        let payload = RpcRequest::GetAccountInfo
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]))
            .to_string();

        let response = self
            .call(
                None,
                &payload,
                max_response_bytes.unwrap_or(MAX_PDA_ACCOUNT_DATA_LENGTH),
                None,
            )
            .await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<Response<Option<UiAccount>>>>(&response)?;

        if let Some(e) = json_response.error {
            return Err(e.into());
        }

        let not_found_error = || RpcError::Text(format!("AccountNotFound: pubkey={}", pubkey));
        let rpc_account = json_response.result.ok_or_else(not_found_error)?;
        let account = rpc_account.value.ok_or_else(not_found_error)?;

        Ok(account.decode())
    }

    pub async fn get_account_info1(
        &self,
        pubkey: &Pubkey,
        config: RpcAccountInfoConfig,
        max_response_bytes: Option<u64>,
        forward: Option<String>,
    ) -> RpcResult<Option<String>> {
        let payload = RpcRequest::GetAccountInfo
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]))
            .to_string();

        let transform = TransformContext::from_name("transform_account".to_owned(), vec![]);
        let response = self
            .call(
                forward,
                &payload,
                max_response_bytes.unwrap_or(MAX_PDA_ACCOUNT_DATA_LENGTH),
                Some(transform),
            )
            .await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<Response<Option<UiAccount>>>>(&response)?;

        if let Some(e) = json_response.error {
            return Err(e.into());
        }

        // let not_found_error = || RpcError::Text(format!("AccountNotFound: pubkey={}", pubkey));
        if json_response.result.is_none() {
            return Ok(None);
        }

        let rpc_account = json_response.result.unwrap();
        Ok(rpc_account
            .value
            .map(|a| serde_json::to_string(&a.decode()).unwrap()))
    }

    ///
    /// Returns the current Solana version running on the node.
    ///
    pub async fn get_version(&self, forward: Option<String>) -> RpcResult<RpcVersionInfo> {
        let payload = RpcRequest::GetVersion
            .build_request_json(self.next_request_id(), Value::Null)
            .to_string();

        let response = self.call(forward, &payload, 128, None).await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<RpcVersionInfo>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns the current health of the node.
    /// A healthy node is one that is within HEALTH_CHECK_SLOT_DISTANCE slots of the latest cluster confirmed slot.
    ///
    pub async fn get_health(&self, forward: Option<String>) -> RpcResult<String> {
        let payload = RpcRequest::GetHealth
            .build_request_json(self.next_request_id(), Value::Null)
            .to_string();

        let response = self.call(forward, &payload, 256, None).await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<String>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns identity and transaction information about a confirmed block in the ledger.
    ///
    pub async fn get_block(
        &self,
        slot: Slot,
        encoding: UiTransactionEncoding,
        forward: Option<String>,
    ) -> RpcResult<EncodedConfirmedBlock> {
        let payload = RpcRequest::GetBlock
            .build_request_json(self.next_request_id(), json!([slot, encoding]))
            .to_string();

        let response = self
            .call(forward, &payload, GET_BLOCK_RESPONSE_SIZE_ESTIMATE, None)
            .await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<EncodedConfirmedBlock>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns the slot that has reached the given or default commitment level.
    ///
    pub async fn get_slot(&self, forward: Option<String>) -> RpcResult<Slot> {
        let payload = RpcRequest::GetSlot
            .build_request_json(self.next_request_id(), Value::Null)
            .to_string();

        let response = self.call(forward, &payload, 128, None).await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<Slot>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns information about the current supply.
    ///
    pub async fn get_supply(
        &self,
        config: RpcSupplyConfig,
        forward: Option<String>,
    ) -> RpcResult<RpcSupply> {
        let payload = RpcRequest::GetSupply
            .build_request_json(self.next_request_id(), json!([config]))
            .to_string();

        let response = self
            .call(forward, &payload, GET_SUPPLY_SIZE_ESTIMATE, None)
            .await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<RpcSupply>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns information about the current epoch.
    ///
    /// Method relies on the `getEpochInfo` RPC call to get the epoch info:
    ///   https://solana.com/docs/rpc/http/getEpochInfo
    ///
    pub async fn get_epoch_info(
        &self,
        config: RpcContextConfig,
        forward: Option<String>,
    ) -> RpcResult<EpochInfo> {
        let payload = RpcRequest::GetEpochInfo
            .build_request_json(self.next_request_id(), json!([config]))
            .to_string();

        let response = self
            .call(forward, &payload, GET_EPOCH_INFO_SIZE_ESTIMATE, None)
            .await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<EpochInfo>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns all accounts owned by the provided program Pubkey.
    ///
    /// Method relies on the `getProgramAccounts` RPC call to get the program accounts:
    ///   https://solana.com/docs/rpc/http/getProgramAccounts
    ///
    pub async fn get_program_accounts(
        &self,
        program_id: &Pubkey,
        config: RpcProgramAccountsConfig,
        max_response_bytes: u64,
        forward: Option<String>,
    ) -> RpcResult<Vec<RpcKeyedAccount>> {
        let payload = RpcRequest::GetProgramAccounts
            .build_request_json(
                self.next_request_id(),
                json!([program_id.to_string(), config]),
            )
            .to_string();

        let response = self
            .call(forward, &payload, max_response_bytes, None)
            .await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<Vec<RpcKeyedAccount>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Requests an airdrop of lamports to a Pubkey
    ///
    /// Method relies on the `requestAirdrop` RPC call to request the airdrop:
    ///   https://solana.com/docs/rpc/http/requestAirdrop
    ///
    pub async fn request_airdrop(
        &self,
        pubkey: &Pubkey,
        lamports: u64,
        forward: Option<String>,
    ) -> RpcResult<String> {
        let payload = RpcRequest::RequestAirdrop
            .build_request_json(
                self.next_request_id(),
                json!([pubkey.to_string(), lamports]),
            )
            .to_string();

        let response = self.call(forward, &payload, 156, None).await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<String>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns signatures for confirmed transactions that include the given address in their accountKeys list.
    /// Returns signatures backwards in time from the provided signature or the most recent confirmed block.
    ///
    /// Method relies on the `getSignaturesForAddress` RPC call to get the signatures for the address:
    ///   https://solana.com/docs/rpc/http/getsignaturesforaddress
    ///
    pub async fn get_signatures_for_address(
        &self,
        pubkey: &Pubkey,
        config: RpcSignaturesForAddressConfig,
        forward: Option<String>,
    ) -> RpcResult<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        let payload = RpcRequest::GetSignaturesForAddress
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]))
            .to_string();

        let max_limit = 1000;

        let response = self
            .call(
                forward,
                &payload,
                SIGNATURE_RESPONSE_SIZE_ESTIMATE * config.limit.unwrap_or(max_limit) as u64,
                None,
            )
            .await?;

        let json_response = serde_json::from_str::<
            JsonRpcResponse<Vec<RpcConfirmedTransactionStatusWithSignature>>,
        >(&response)?;

        log!(
            DEBUG,
            "[ic-solana] get_signatures_for_address json_response: {:?}",
            json_response
        );

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns the statuses of a list of transaction signatures.
    ///
    /// Method relies on the `getSignatureStatuses` RPC call to get the statuses for the signatures:
    ///   https://solana.com/docs/rpc/http/getSignatureStatuses
    ///
    pub async fn get_signature_statuses(
        &self,
        signatures: &[Signature],
        config: RpcSignatureStatusConfig,
        forward: Option<String>,
    ) -> RpcResult<Vec<TransactionStatus>> {
        let sigs = signatures.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let payload = RpcRequest::GetSignatureStatuses
            .build_request_json(self.next_request_id(), json!([sigs, config]))
            .to_string();

        // let transform =
        //     TransformContext::from_name("transform_signature_statuses".to_owned(), vec![]);

        let response = self
            .call(
                forward,
                &payload,
                TRANSACTION_STATUS_RESPONSE_SIZE_ESTIMATE,
                None,
            )
            .await?;
        log!(
            DEBUG,
            "[ic-solana] get_signature_statuses response: {:?}",
            response
        );
        let json_response = serde_json::from_str::<
            JsonRpcResponse<Response<Option<Vec<TransactionStatus>>>>,
        >(&response)?;

        log!(
            DEBUG,
            "[ic-solana] get_signature_statuses json_response: {:?}",
            json_response
        );

        if let Some(e) = json_response.error {
            return Err(e.into());
        }

        let not_found_error =
            || RpcError::Text(format!("StatusNotFound: signatures={:?}", signatures));
        let resp = json_response.result.ok_or_else(not_found_error)?;
        let status = resp.value.ok_or_else(not_found_error)?;
        Ok(status)
    }

    ///
    /// Returns transaction details for a confirmed transaction.
    ///
    /// Method relies on the `getTransaction` RPC call to get the transaction data:
    ///   https://solana.com/docs/rpc/http/getTransaction
    ///
    pub async fn get_transaction(
        &self,
        signature: &Signature,
        config: RpcTransactionConfig,
        forward: Option<String>,
    ) -> RpcResult<EncodedConfirmedTransactionWithStatusMeta> {
        let payload = RpcRequest::GetTransaction
            .build_request_json(
                self.next_request_id(),
                json!([signature.to_string(), config]),
            )
            .to_string();

        let response = self
            .call(forward, &payload, TRANSACTION_RESPONSE_SIZE_ESTIMATE, None)
            .await?;

        let json_response = serde_json::from_str::<
            JsonRpcResponse<EncodedConfirmedTransactionWithStatusMeta>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    pub async fn get_transaction1(
        &self,
        signature: &Signature,
        config: RpcTransactionConfig,
        forward: Option<String>,
    ) -> RpcResult<String> {
        let payload = RpcRequest::GetTransaction
            .build_request_json(
                self.next_request_id(),
                json!([signature.to_string(), config]),
            )
            .to_string();

        let response = self
            .call(forward, &payload, TX_MEMO_RESP_SIZE_ESTIMATE, None)
            .await?;

        // let json_response = serde_json::from_str::<
        //     JsonRpcResponse<String>,
        // >(&response)?;

        // if let Some(e) = json_response.error {
        //     Err(e.into())
        // } else {
        //     Ok(serde_json::to_string(&json_response.result.unwrap()).unwrap())
        // }
        Ok(response)
    }

    ///
    /// Submits a signed transaction to the cluster for processing.
    /// This method does not alter the transaction in any way; it relays the transaction created by clients to the node as-is.
    /// If the node's rpc service receives the transaction, this method immediately succeeds,
    /// without waiting for any confirmations.
    /// A successful response from this method does not guarantee the transaction is processed or confirmed by the cluster.
    ///
    /// Use [RpcClient::get_signature_statuses] to ensure a transaction is processed and confirmed.
    ///
    /// Method relies on the `sendTransaction` RPC call to send the transaction:
    ///   https://solana.com/docs/rpc/http/sendTransaction
    ///
    pub async fn send_transaction(
        &self,
        tx: Transaction,
        config: RpcSendTransactionConfig,
        forward: Option<String>,
    ) -> RpcResult<Signature> {
        let serialized = tx.serialize();

        let raw_tx = match config.encoding {
            None | Some(UiTransactionEncoding::Base58) => bs58::encode(serialized).into_string(),
            Some(UiTransactionEncoding::Base64) => BASE64_STANDARD.encode(serialized),
            Some(e) => {
                return Err(RpcError::Text(format!(
                    "Unsupported encoding: {e}. Supported encodings: base58, base64"
                )));
            }
        };

        let payload = RpcRequest::SendTransaction
            .build_request_json(self.next_request_id(), json!([raw_tx, config]))
            .to_string();

        let response = self.call(forward, &payload, 156, None).await?;

        let json_response = serde_json::from_str::<JsonRpcResponse<String>>(&response)?;

        match json_response.result {
            Some(result) => Signature::from_str(&result)
                .map_err(|_| RpcError::Text("Failed to parse signature".to_string())),
            None => Err(json_response
                .error
                .map(|e| e.into())
                .unwrap_or_else(|| RpcError::Text("Unknown error".to_string()))),
        }
    }

    ///
    /// Returns minimum balance required to make account rent exempt.
    ///
    /// Method relies on the `getminimumbalanceforrentexemption` RPC call to get the balance:
    ///   https://solana.com/docs/rpc/http/getminimumbalanceforrentexemption
    ///
    pub async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
        forward: Option<String>,
    ) -> RpcResult<u64> {
        let payload = RpcRequest::GetMinimumBalanceForRentExemption
            .build_request_json(self.next_request_id(), json!([data_len]))
            .to_string();

        let response = self.call(forward, &payload, 156, None).await?;

        let json_response =
            serde_json::from_str::<JsonRpcResponse<OptionalContext<u64>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Submits a signed transaction to the cluster for processing.

    ///
    /// Method relies on the `sendTransaction` RPC call to send the transaction:
    ///   https://solana.com/docs/rpc/http/sendTransaction
    ///
    pub async fn simulate_transaction(
        &self,
        tx: Transaction,
        config: RpcSimulateTransactionConfig,
        forward: Option<String>,
    ) -> RpcResult<Option<u64>> {
        let serialized = tx.serialize();

        let raw_tx = match config.encoding {
            None | Some(UiTransactionEncoding::Base58) => bs58::encode(serialized).into_string(),
            Some(UiTransactionEncoding::Base64) => BASE64_STANDARD.encode(serialized),
            Some(e) => {
                return Err(RpcError::Text(format!(
                    "Unsupported encoding: {e}. Supported encodings: base58, base64"
                )));
            }
        };

        let payload = RpcRequest::SimulateTransaction
            .build_request_json(self.next_request_id(), json!([raw_tx, config]))
            .to_string();

        let response = self
            .call(forward, &payload, TX_MEMO_RESP_SIZE_ESTIMATE, None)
            .await?;

        log!(
            DEBUG,
            "[ic-solana] simulate_transaction response: {}",
            response
        );
        let json_response = serde_json::from_str::<
            JsonRpcResponse<Response<Option<RpcSimulateTransactionResult>>>,
        >(&response)?;

        log!(
            DEBUG,
            "[ic-solana] simulate_transaction json_response: {:?}",
            json_response
        );
        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            log!(
                DEBUG,
                "[ic-solana] simulate_transaction json_response.result: {:?}",
                json_response.result
            );
            let sim_result = json_response.result.unwrap().value.unwrap();
            if let Some(err) = sim_result.err {
                return Err(RpcError::Text(err.to_string()));
            }
            // Otherwise, we can get the compute units from the simulation result
            let units = sim_result
                .units_consumed
                .map(|units| (units as f64 * 1.20) as u64);
            log!(
                DEBUG,
                "[ic-solana] simulate_transaction units_consumed: {:?}",
                units
            );
            Ok(units)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_compute_units_4_create_mint() {
        let json_data = r#"
        {
            "jsonrpc": "2.0",
            "result": {
                "context": {
                    "apiVersion": "2.0.13",
                    "slot": 334359643
                },
                "value": {
                    "accounts": null,
                    "err": null,
                    "innerInstructions": null,
                    "logs": [
                        "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s invoke [1]",
                        "Program log: IX: Create",
                        "Program 11111111111111111111111111111111 invoke [2]",
                        "Program 11111111111111111111111111111111 success",
                        "Program 11111111111111111111111111111111 invoke [2]",
                        "Program 11111111111111111111111111111111 success",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
                        "Program log: Instruction: InitializeMint2",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2828 of 180914 compute units",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                        "Program log: Allocate space for the account",
                        "Program 11111111111111111111111111111111 invoke [2]",
                        "Program 11111111111111111111111111111111 success",
                        "Program log: Assign the account to the owning program",
                        "Program 11111111111111111111111111111111 invoke [2]",
                        "Program 11111111111111111111111111111111 success",
                        "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s consumed 54137 of 200000 compute units",
                        "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s success"
                    ],
                    "replacementBlockhash": {
                        "blockhash": "AhckRh63HXBN6e1RK7h924vJSQzbsZJL2HVQTxMNF2KA",
                        "lastValidBlockHeight": 322564880
                    },
                    "returnData": null,
                    "unitsConsumed": 54137
                }
            },
            "id": 0
        }
        "#;

        let json_response = serde_json::from_str::<
            JsonRpcResponse<Response<Option<RpcSimulateTransactionResult>>>,
        >(&json_data)
        .expect("Failed to parse JSON");

        println!("json_response: {:#?}", json_response);
    }

    #[test]
    fn test_get_compute_units_4_create_ata() {
        let json_data = r#"
       {
            "jsonrpc": "2.0",
            "result": {
                "context": {
                    "apiVersion": "2.0.13",
                    "slot": 334353176
                },
                "value": {
                    "accounts": null,
                    "err": null,
                    "innerInstructions": null,
                    "logs": [
                        "Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL invoke [1]",
                        "Program log: Create",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
                        "Program log: Instruction: GetAccountDataSize",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 1622 of 193025 compute units",
                        "Program return: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA pQAAAAAAAAA=",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                        "Program 11111111111111111111111111111111 invoke [2]",
                        "Program 11111111111111111111111111111111 success",
                        "Program log: Initialize the associated token account",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
                        "Program log: Instruction: InitializeImmutableOwner",
                        "Program log: Please upgrade to SPL Token 2022 for immutable owner support",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 1405 of 186385 compute units",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
                        "Program log: Instruction: InitializeAccount3",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4241 of 182501 compute units",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                        "Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL consumed 22044 of 200000 compute units",
                        "Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL success"
                    ],
                    "replacementBlockhash": {
                        "blockhash": "B2JfaBryMAf9iuJG5rdjvJTAHYMtgeNDR3xv3pTdrknQ",
                        "lastValidBlockHeight": 322558422
                    },
                    "returnData": null,
                    "unitsConsumed": 22044
                }
            },
            "id": 2
        }
        "#;

        let json_response = serde_json::from_str::<
            JsonRpcResponse<Response<Option<RpcSimulateTransactionResult>>>,
        >(&json_data)
        .expect("Failed to parse JSON");

        println!("json_response: {:#?}", json_response);
    }

    #[test]
    fn test_get_compute_units_4_mint_to() {
        let json_data = r#"
        {
            "jsonrpc": "2.0",
            "result": {
                "context": {
                    "apiVersion": "2.0.13",
                    "slot": 334357572
                },
                "value": {
                    "accounts": null,
                    "err": null,
                    "innerInstructions": null,
                    "logs": [
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
                        "Program log: Instruction: MintTo",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4537 of 200000 compute units",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success"
                    ],
                    "replacementBlockhash": {
                        "blockhash": "A7owRqh6GfLGxvJVPNVso1h12KNaK57NgtgVoxZQ3gRm",
                        "lastValidBlockHeight": 322562809
                    },
                    "returnData": null,
                    "unitsConsumed": 4537
                }
            },
            "id": 1
        }
        "#;

        let json_response = serde_json::from_str::<
            JsonRpcResponse<Response<Option<RpcSimulateTransactionResult>>>,
        >(&json_data)
        .expect("Failed to parse JSON");

        println!("json_response: {:#?}", json_response);
    }

    #[test]
    fn test_get_compute_units_4_transfer() {
        let json_data = r#"
        {
            "jsonrpc": "2.0",
            "result": {
                "context": {
                    "apiVersion": "2.0.13",
                    "slot": 334350609
                },
                "value": {
                    "accounts": null,
                    "err": null,
                    "innerInstructions": null,
                    "logs": [
                        "Program 11111111111111111111111111111111 invoke [1]",
                        "Program 11111111111111111111111111111111 success"
                    ],
                    "replacementBlockhash": {
                        "blockhash": "6Do2geaLv6ZoMPRa1PKDKcGzRKnfvCJAPbTS9RBXL8kq",
                        "lastValidBlockHeight": 322555859
                    },
                    "returnData": null,
                    "unitsConsumed": 150
                }
            },
            "id": 1
        }
        "#;

        let json_response = serde_json::from_str::<
            JsonRpcResponse<Response<Option<RpcSimulateTransactionResult>>>,
        >(&json_data)
        .expect("Failed to parse JSON");

        println!("json_response: {:#?}", json_response);
    }
}
