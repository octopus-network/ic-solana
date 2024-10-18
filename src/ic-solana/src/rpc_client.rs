use {
    crate::{
        constants::*,
        request::RpcRequest,
        response::{
            OptionalContext, Response, RpcBlockProduction, RpcBlockhash,
            RpcConfirmedTransactionStatusWithSignature, RpcKeyedAccount, RpcSupply,
            RpcTokenAccountBalance, RpcVersionInfo,
        },
        types::{
            Account, BlockHash, Cluster, CommitmentConfig,
            EncodedConfirmedTransactionWithStatusMeta, EpochInfo, Pubkey, RpcAccountInfoConfig,
            RpcBlockProductionConfig, RpcContextConfig, RpcProgramAccountsConfig,
            RpcSendTransactionConfig, RpcSignatureStatusConfig, RpcSignaturesForAddressConfig,
            RpcSupplyConfig, RpcTransactionConfig, Signature, Slot, TokenAccountsFilter,
            Transaction, TransactionDetails, TransactionStatus, UiAccount, UiConfirmedBlock,
            UiTokenAmount, UiTransactionEncoding,
        },
    },
    anyhow::Result,
    base64::{prelude::BASE64_STANDARD, Engine},
    candid::CandidType,
    ic_canister_log::log,
    ic_cdk::api::management_canister::http_request::{
        http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
    },
    ic_solana_common::{
        add_metric_entry,
        logs::DEBUG,
        metrics::{MetricRpcHost, MetricRpcMethod},
    },
    serde::Deserialize,
    serde_json::{json, Value},
    std::{cell::RefCell, collections::HashMap, str::FromStr},
};

thread_local! {
    static NEXT_ID: RefCell<u64> = RefCell::default();
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub result: Option<T>,
    pub error: Option<JsonRpcError>,
    pub id: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error, Deserialize, CandidType)]
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

pub type RequestCostCalculator = fn(&CanisterHttpRequestArgument) -> (u128, u128);

#[derive(Clone, Debug)]
pub struct RpcClient {
    pub cluster: Cluster,
    pub commitment_config: CommitmentConfig,
    pub headers: Option<Vec<HttpHeader>>,
    pub cost_calculator: Option<RequestCostCalculator>,
    pub transform_context: Option<TransformContext>,
    pub is_demo_active: bool,
    pub hosts_blocklist: &'static [&'static str],
    pub extra_response_bytes: u64,
}

impl RpcClient {
    pub fn new(network: &str) -> Self {
        Self {
            cluster: Cluster::from_str(network).expect("Failed to parse the network"),
            commitment_config: CommitmentConfig::confirmed(),
            cost_calculator: None,
            headers: None,
            transform_context: None,
            is_demo_active: false,
            hosts_blocklist: &[],
            extra_response_bytes: 2 * 1024, // 2KB
        }
    }

    pub fn with_headers(mut self, headers: impl Into<Vec<HttpHeader>>) -> Self {
        self.headers = Some(headers.into());
        self
    }

    pub fn with_commitment(mut self, commitment_config: CommitmentConfig) -> Self {
        self.commitment_config = commitment_config;
        self
    }

    pub fn with_request_cost_calculator(mut self, cost_calculator: RequestCostCalculator) -> Self {
        self.cost_calculator = Some(cost_calculator);
        self
    }

    pub fn with_transform_context(mut self, transform_context: TransformContext) -> Self {
        self.transform_context = Some(transform_context);
        self
    }

    pub fn with_demo(mut self, is_demo_active: bool) -> Self {
        self.is_demo_active = is_demo_active;
        self
    }

    pub fn with_hosts_blocklist(mut self, hosts_blocklist: &'static [&'static str]) -> Self {
        self.hosts_blocklist = hosts_blocklist;
        self
    }

    pub fn with_response_extra_size(mut self, size: u64) -> Self {
        self.extra_response_bytes = size;
        self
    }

    /// Asynchronously sends an HTTP POST request to the specified URL with the given payload and
    /// maximum response bytes and returns the response as a string.
    /// This function calculates the required cycles for the HTTP request and logs the request
    /// details and response status. It uses a transformation named "cleanup_response" for the
    /// response body.
    ///
    /// # Arguments
    ///
    /// * `payload` - JSON payload to be sent in the HTTP request.
    /// * `max_response_bytes` - A u64 value representing the maximum number of bytes for the response.
    ///
    /// # Returns
    ///
    /// * `RpcResult<String>` - A result type that contains the response body as a string if the request
    ///   is successful, or an `RpcError` if the request fails.
    ///
    /// # Errors
    ///
    /// This function returns an `RpcError` in the following cases:
    /// * If the response body cannot be parsed as a UTF-8 string, a `ParseError` is returned.
    /// * If the HTTP request fails, an `RpcRequestError` is returned with the error details.
    ///
    pub async fn call(&self, payload: &Value, max_response_bytes: u64) -> RpcResult<Vec<u8>> {
        let url = self.cluster.url();

        let mut headers = self.headers.clone().unwrap_or_default();
        if !headers
            .iter()
            .any(|header| header.name.to_lowercase() == "content-type")
        {
            headers.push(HttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            });
        }

        let body = serde_json::to_vec(payload).map_err(|e| RpcError::ParseError(e.to_string()))?;

        let request = CanisterHttpRequestArgument {
            url: url.to_string(),
            max_response_bytes: Some(max_response_bytes + self.extra_response_bytes),
            method: HttpMethod::POST,
            headers,
            body: Some(body),
            transform: self.transform_context.clone(),
        };

        // Calculate cycles if a calculator is provided
        let (cycles_cost, cycles_cost_with_collateral) = self
            .cost_calculator
            .as_ref()
            .map_or((0, 0), |calc| calc(&request));

        let parsed_url = url::Url::parse(url)
            .map_err(|_| RpcError::ParseError(format!("Invalid URL: {}", url)))?;

        let host = parsed_url.host_str().ok_or_else(|| {
            RpcError::ParseError(format!("Error parsing hostname from URL: {}", url))
        })?;

        let rpc_host = MetricRpcHost(host.to_string());
        let rpc_method = MetricRpcMethod(payload["method"].to_string());

        if self.hosts_blocklist.contains(&host) {
            add_metric_entry!(err_host_not_allowed, rpc_host.clone(), 1);
            return Err(RpcError::Text(format!(
                "Disallowed RPC service host: {}",
                host
            )));
        }

        // Handle cycle accounting if not in demo mode
        if !self.is_demo_active {
            let cycles_available = ic_cdk::api::call::msg_cycles_available128();
            if cycles_available < cycles_cost_with_collateral {
                return Err(RpcError::RpcRequestError(format!(
                    "Insufficient cycles: available {}, required {} (with collateral).",
                    cycles_available, cycles_cost_with_collateral
                )));
            }
            ic_cdk::api::call::msg_cycles_accept128(cycles_cost);
            add_metric_entry!(
                cycles_charged,
                (rpc_method.clone(), rpc_host.clone()),
                cycles_cost
            );
        }

        log!(
            DEBUG,
            "Calling url: {url} with payload: {payload}. Cycles: {cycles_cost}"
        );

        add_metric_entry!(requests, (rpc_method.clone(), rpc_host.clone()), 1);

        match http_request(request, cycles_cost).await {
            Ok((response,)) => {
                let body_len = response.body.len();
                let body_str = std::str::from_utf8(&response.body)
                    .map_err(|e| RpcError::ParseError(e.to_string()))?;

                log!(
                    DEBUG,
                    "Got response (with {} bytes): {} from url: {} with status: {}",
                    body_len,
                    body_str,
                    url,
                    response.status
                );

                let status: u32 = response.status.0.try_into().unwrap_or(0);
                add_metric_entry!(responses, (rpc_method, rpc_host, status.into()), 1);

                Ok(response.body)
            }
            Err((r, m)) => {
                add_metric_entry!(err_http_outcall, (rpc_method, rpc_host), 1);
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
    pub async fn get_latest_blockhash(&self, config: RpcContextConfig) -> RpcResult<BlockHash> {
        let payload = RpcRequest::GetLatestBlockhash
            .build_request_json(self.next_request_id(), json!([config]));

        let response = self.call(&payload, 156).await?;

        let json_response =
            serde_json::from_slice::<JsonRpcResponse<OptionalContext<RpcBlockhash>>>(&response)?;

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
    pub async fn get_balance(&self, pubkey: &Pubkey, config: RpcContextConfig) -> RpcResult<u64> {
        let payload = RpcRequest::GetBalance
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]));

        let response = self.call(&payload, 156).await?;

        let json_response =
            serde_json::from_slice::<JsonRpcResponse<OptionalContext<u64>>>(&response)?;

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
    ) -> RpcResult<UiTokenAmount> {
        let payload = RpcRequest::GetTokenAccountBalance.build_request_json(
            self.next_request_id(),
            json!([pubkey.to_string(), commitment]),
        );

        let response = self.call(&payload, 256).await?;

        let json_response =
            serde_json::from_slice::<JsonRpcResponse<OptionalContext<UiTokenAmount>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns all SPL Token accounts by approved Delegate.
    ///
    /// Method relies on the `getTokenAccountsByDelegate` RPC call to get the token balance:
    ///   https://solana.com/docs/rpc/http/gettokenaccountsbydelegate
    ///
    pub async fn get_token_accounts_by_delegate(
        &self,
        pubkey: &Pubkey,
        token_accounts_filter: TokenAccountsFilter,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<Vec<RpcKeyedAccount>> {
        let payload = RpcRequest::GetTokenAccountsByDelegate.build_request_json(
            self.next_request_id(),
            json!([pubkey.to_string(), token_accounts_filter]),
        );

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(GET_TOKEN_ACCOUNTS_SIZE_ESTIMATE),
            )
            .await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<OptionalContext<Vec<RpcKeyedAccount>>>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns all SPL Token accounts by token owner
    ///
    /// Method relies on the `getTokenAccountsByOwner` RPC call to get the token balance:
    ///   https://solana.com/docs/rpc/http/gettokenaccountsbyowner
    ///
    pub async fn get_token_accounts_by_owner(
        &self,
        pubkey: &Pubkey,
        token_accounts_filter: TokenAccountsFilter,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<Vec<RpcKeyedAccount>> {
        let payload = RpcRequest::GetTokenAccountsByOwner.build_request_json(
            self.next_request_id(),
            json!([pubkey.to_string(), token_accounts_filter]),
        );

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(GET_TOKEN_ACCOUNTS_SIZE_ESTIMATE),
            )
            .await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<OptionalContext<Vec<RpcKeyedAccount>>>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns the 20 largest accounts of a particular SPL Token type.
    ///
    /// Method relies on the `getTokenLargestAccounts` RPC call to get the token balance:
    ///   https://solana.com/docs/rpc/http/gettokenlargestaccounts
    ///
    pub async fn get_token_largest_accounts(
        &self,
        mint: &Pubkey,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<Vec<RpcTokenAccountBalance>> {
        let payload = RpcRequest::GetTokenLargestAccounts
            .build_request_json(self.next_request_id(), json!([mint.to_string()]));

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(GET_TOKEN_LARGEST_ACCOUNTS_SIZE_ESTIMATE),
            )
            .await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<OptionalContext<Vec<RpcTokenAccountBalance>>>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns the total supply of an SPL Token type.
    ///
    /// Method relies on the `getTokenSupply` RPC call to get the token balance:
    ///   https://solana.com/docs/rpc/http/gettokensupply
    ///
    pub async fn get_token_supply(
        &self,
        mint: &Pubkey,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<UiTokenAmount> {
        let payload = RpcRequest::GetTokenSupply
            .build_request_json(self.next_request_id(), json!([mint.to_string()]));

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(GET_TOKEN_SUPPLY_SIZE_ESTIMATE),
            )
            .await?;

        let json_response =
            serde_json::from_slice::<JsonRpcResponse<OptionalContext<UiTokenAmount>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns all information associated with the account of the provided Pubkey.
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
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]));

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(MAX_PDA_ACCOUNT_DATA_LENGTH),
            )
            .await?;

        let json_response =
            serde_json::from_slice::<JsonRpcResponse<Response<Option<UiAccount>>>>(&response)?;

        if let Some(e) = json_response.error {
            return Err(e.into());
        }

        let not_found_error = || RpcError::Text(format!("AccountNotFound: pubkey={}", pubkey));
        let rpc_account = json_response.result.ok_or_else(not_found_error)?;
        let account = rpc_account.value.ok_or_else(not_found_error)?;

        Ok(account.decode())
    }

    ///
    /// Returns the current Solana version running on the node.
    ///
    /// Method relies on the `getVersion` RPC call to get the version info:
    ///   https://solana.com/docs/rpc/http/getVersion
    ///
    pub async fn get_version(&self) -> RpcResult<RpcVersionInfo> {
        let payload =
            RpcRequest::GetVersion.build_request_json(self.next_request_id(), Value::Null);

        let response = self.call(&payload, 128).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<RpcVersionInfo>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns the current health of the node.
    /// A healthy node is one that is within HEALTH_CHECK_SLOT_DISTANCE slots of the latest cluster-confirmed slot.
    ///
    /// Method relies on the `getHealth` RPC call to get the health status:
    ///   https://solana.com/docs/rpc/http/getHealth
    ///
    pub async fn get_health(&self) -> RpcResult<String> {
        let payload = RpcRequest::GetHealth.build_request_json(self.next_request_id(), Value::Null);

        let response = self.call(&payload, 256).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<String>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns identity and transaction information about a confirmed block in the ledger.
    ///
    /// Method relies on the `getBlock` RPC call to get the block:
    ///   https://solana.com/docs/rpc/http/getBlock
    ///
    pub async fn get_block(
        &self,
        slot: Slot,
        encoding: UiTransactionEncoding,
        transaction_details: TransactionDetails,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<UiConfirmedBlock> {
        let payload = RpcRequest::GetBlock.build_request_json(
            self.next_request_id(),
            json!([slot, { "encoding": encoding, "maxSupportedTransactionVersion": 0, "transactionDetails": transaction_details }]),
        );

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(GET_BLOCK_RESPONSE_SIZE_ESTIMATE),
            )
            .await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<UiConfirmedBlock>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns a list of confirmed blocks between two slots.
    ///
    /// Method relies on the `getBlocks` RPC call to get the blocks:
    ///   https://solana.com/docs/rpc/http/getBlocks
    ///
    pub async fn get_blocks(
        &self,
        start_slot: Slot,
        end_slot: Option<Slot>,
    ) -> RpcResult<Vec<u64>> {
        let payload = RpcRequest::GetBlocks
            .build_request_json(self.next_request_id(), json!([start_slot, end_slot]));

        // Total response size estimation
        let end_slot = end_slot.unwrap_or(start_slot + MAX_GET_BLOCKS_RANGE);
        let max_slot_str_len = end_slot.to_string().len() as u64;
        let slot_range = end_slot.saturating_sub(start_slot);
        let commas_size = if slot_range > 0 { slot_range - 1 } else { 0 };
        let max_response_bytes = 36 + max_slot_str_len * slot_range + commas_size;

        let response = self.call(&payload, max_response_bytes).await?;
        let json_response = serde_json::from_slice::<JsonRpcResponse<Vec<u64>>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns the current block height of the node
    ///
    /// Method relies on the `getBlockHeight` RPC call to get the block height:
    ///   https://solana.com/docs/rpc/http/getBlockHeight
    ///
    pub async fn get_block_height(&self, commitment: Option<CommitmentConfig>) -> RpcResult<u64> {
        let payload = RpcRequest::GetBlockHeight.build_request_json(
            self.next_request_id(),
            json!([commitment.unwrap_or_default()]),
        );

        let response = self.call(&payload, 45).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<u64>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns recent block production information from the current or previous epoch.
    ///
    /// Method relies on the `getBlockProduction` RPC call to get the block production:
    ///   https://solana.com/docs/rpc/http/getBlockProduction
    ///
    pub async fn get_block_production(
        &self,
        config: RpcBlockProductionConfig,
    ) -> RpcResult<RpcBlockProduction> {
        let payload = RpcRequest::GetBlockProduction
            .build_request_json(self.next_request_id(), json!([config]));

        let response = self.call(&payload, 100_000).await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<OptionalContext<RpcBlockProduction>>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
    }

    ///
    /// Returns the slot that has reached the given or default commitment level.
    ///
    /// Method relies on the `getSlot` RPC call to get the slot:
    ///   https://solana.com/docs/rpc/http/getSlot
    ///
    pub async fn get_slot(&self) -> RpcResult<Slot> {
        let payload = RpcRequest::GetSlot.build_request_json(self.next_request_id(), Value::Null);

        let response = self.call(&payload, 128).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<Slot>>(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Returns information about the current supply.
    ///
    /// Method relies on the `getSupply` RPC call to get the supply:
    ///   https://solana.com/docs/rpc/http/getSupply
    ///
    pub async fn get_supply(&self, config: RpcSupplyConfig) -> RpcResult<RpcSupply> {
        let payload =
            RpcRequest::GetSupply.build_request_json(self.next_request_id(), json!([config]));

        let response = self.call(&payload, GET_SUPPLY_SIZE_ESTIMATE).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<RpcSupply>>(&response)?;

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
    pub async fn get_epoch_info(&self, config: RpcContextConfig) -> RpcResult<EpochInfo> {
        let payload =
            RpcRequest::GetEpochInfo.build_request_json(self.next_request_id(), json!([config]));

        let response = self.call(&payload, GET_EPOCH_INFO_SIZE_ESTIMATE).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<EpochInfo>>(&response)?;

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
    ) -> RpcResult<Vec<RpcKeyedAccount>> {
        let payload = RpcRequest::GetProgramAccounts.build_request_json(
            self.next_request_id(),
            json!([program_id.to_string(), config]),
        );

        let response = self.call(&payload, max_response_bytes).await?;

        let json_response =
            serde_json::from_slice::<JsonRpcResponse<Vec<RpcKeyedAccount>>>(&response)?;

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
    pub async fn request_airdrop(&self, pubkey: &Pubkey, lamports: u64) -> RpcResult<String> {
        let payload = RpcRequest::RequestAirdrop.build_request_json(
            self.next_request_id(),
            json!([pubkey.to_string(), lamports]),
        );

        let response = self.call(&payload, 156).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<String>>(&response)?;

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
    ) -> RpcResult<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        let payload = RpcRequest::GetSignaturesForAddress
            .build_request_json(self.next_request_id(), json!([pubkey.to_string(), config]));

        let default_limit = 1000;

        let response = self
            .call(
                &payload,
                SIGNATURE_RESPONSE_SIZE_ESTIMATE * config.limit.unwrap_or(default_limit) as u64,
            )
            .await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<Vec<RpcConfirmedTransactionStatusWithSignature>>,
        >(&response)?;

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
    ) -> RpcResult<Vec<Option<TransactionStatus>>> {
        let signatures = signatures.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        let payload = RpcRequest::GetSignatureStatuses
            .build_request_json(self.next_request_id(), json!([signatures, config]));

        // Estimate 256 bytes per transaction status to account for errors and metadata
        let max_response_bytes =
            signatures.len() as u64 * TRANSACTION_STATUS_RESPONSE_SIZE_ESTIMATE;

        let response = self.call(&payload, max_response_bytes).await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<OptionalContext<Vec<Option<TransactionStatus>>>>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap().parse_value())
        }
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
        max_response_bytes: Option<u64>,
    ) -> RpcResult<EncodedConfirmedTransactionWithStatusMeta> {
        let payload = RpcRequest::GetTransaction
            .build_request_json(self.next_request_id(), json!([signature.as_str(), config]));

        let response = self
            .call(
                &payload,
                max_response_bytes.unwrap_or(TRANSACTION_RESPONSE_SIZE_ESTIMATE),
            )
            .await?;

        let json_response = serde_json::from_slice::<
            JsonRpcResponse<EncodedConfirmedTransactionWithStatusMeta>,
        >(&response)?;

        if let Some(e) = json_response.error {
            Err(e.into())
        } else {
            Ok(json_response.result.unwrap())
        }
    }

    ///
    /// Method relies on the `getTransaction` RPC call to get the transaction data:
    /// https://solana.com/docs/rpc/http/gettransaction
    /// It is using a batch request to get multiple transactions at once.
    ///
    /// cURL Example:
    /// curl -X POST -H "Content-Type: application/json" -d '[
    ///    {"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["1"]}
    ///    {"jsonrpc":"2.0","id":2,"method":"getTransaction","params":["2"]}
    /// ]' http://localhost:8899
    ///
    pub async fn get_transactions(
        &self,
        signatures: Vec<&str>,
        config: RpcTransactionConfig,
        max_response_bytes: Option<u64>,
    ) -> RpcResult<HashMap<String, RpcResult<Option<EncodedConfirmedTransactionWithStatusMeta>>>>
    {
        let rpc_request = signatures
            .iter()
            .map(|signature| {
                RpcRequest::GetTransaction
                    .build_request_json(self.next_request_id(), json!([signature, config]))
            })
            .collect();

        let response = self
            .call(
                &Value::Array(rpc_request),
                max_response_bytes.unwrap_or_else(|| {
                    signatures.len() as u64 * TRANSACTION_RESPONSE_SIZE_ESTIMATE
                }),
            )
            .await?;

        let json_response = serde_json::from_slice::<
            Vec<JsonRpcResponse<EncodedConfirmedTransactionWithStatusMeta>>,
        >(&response)?;

        let result = json_response
            .into_iter()
            .enumerate()
            .map(|(index, res)| {
                let entity = if let Some(error) = res.error {
                    Err(RpcError::RpcResponseError {
                        code: error.code,
                        message: error.message,
                        data: None,
                    })
                } else {
                    Ok(res.result)
                };
                (signatures[index].to_string(), entity)
            })
            .collect::<HashMap<_, _>>();

        Ok(result)
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
            .build_request_json(self.next_request_id(), json!([raw_tx, config]));

        let response = self.call(&payload, 156).await?;

        let json_response = serde_json::from_slice::<JsonRpcResponse<String>>(&response)?;

        match json_response.result {
            Some(result) => Signature::from_str(&result)
                .map_err(|_| RpcError::Text("Failed to parse signature".to_string())),
            None => Err(json_response
                .error
                .map(|e| e.into())
                .unwrap_or_else(|| RpcError::Text("Unknown error".to_string()))),
        }
    }
}
