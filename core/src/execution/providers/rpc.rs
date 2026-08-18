use std::collections::{HashMap, HashSet};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use alloy::transports::{http::Http, utils::guess_local_url};
use alloy::{
    consensus::BlockHeader,
    eips::{BlockId, BlockNumberOrTag},
    network::{
        primitives::HeaderResponse, BlockResponse, ReceiptResponse, TransactionBuilder,
        TransactionResponse,
    },
    primitives::{Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rlp,
    rpc::{
        client::{ClientBuilder, RpcClient},
        types::{AccessListItem, Filter, FilterBlockOption, Log},
    },
    transports::layers::RetryBackoffLayer,
};
use alloy_trie::{TrieAccount, KECCAK_EMPTY};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::future::{join_all, try_join_all};
use reqwest::Url;

use helios_common::{
    execution_provider::{
        AccountProvider, BlockProvider, ExecutionHintProvider, ExecutionProvider, LogProvider,
        ReceiptProvider, TransactionProvider,
    },
    network_spec::NetworkSpec,
    types::Account,
};

use crate::execution::{
    constants::PARALLEL_QUERY_BATCH_SIZE,
    errors::ExecutionError,
    proof::{
        verify_account_proof, verify_block_receipts, verify_code_hash_proof, verify_storage_proof,
    },
    providers::historical::HistoricalBlockProvider,
};

use super::utils::ensure_logs_match_filter;

// Implementation for unit type to provide no historical block support
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec> HistoricalBlockProvider<N> for () {
    async fn get_historical_block<E>(
        &self,
        _block_id: BlockId,
        _full_tx: bool,
        _execution_provider: &E,
    ) -> Result<Option<N::BlockResponse>>
    where
        E: BlockProvider<N> + AccountProvider<N>,
    {
        Ok(None)
    }
}

pub struct RpcExecutionProvider<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>>
{
    provider: RootProvider<N>,
    block_provider: B,
    historical_provider: Option<H>,
}

/// Builds the HTTP client the execution RPC calls travel on.
///
/// An ACL check fans out into roughly a dozen state calls. On a fresh connection
/// each one pays DNS, the TCP handshake and the TLS handshake before the answer
/// starts; on a connection that already exists it pays the round trip only. The
/// difference is large: measured from the mainnet hosts, a cold call costs 84 ms
/// (Limburg) and 115 ms (Gravelines) against 18 ms and 20 ms warm. Alloy's
/// default transport leaves these settings unset, so the pool is not kept warm
/// between calls and the fan-out cannot share one connection.
///
/// The settings match the sibling `HttpVerifiableApi` client, with one
/// deliberate difference: HTTP/2 is left to ALPN instead of being forced. The
/// upstream is `http://localhost:8545` in the standard deployment, and forcing
/// prior knowledge would break a plain HTTP/1.1 upstream.
#[cfg(not(target_arch = "wasm32"))]
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        // Keep connections ready per upstream, and keep them indefinitely: the
        // fan-out is bursty, so an idle timeout would throw away exactly the
        // connections the next request needs.
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(None)
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true)
        // Hold the HTTP/2 connection open through idle gaps, so a pooled
        // connection is still usable when the next check arrives.
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(30))
        .http2_keep_alive_while_idle(true)
        // Resolve in process and cache to the record TTL. The mesh resolver
        // answers over the same relayed path as the RPC call, at 7 ms to 26 ms
        // per lookup, and nothing between it and the caller caches.
        .hickory_dns(true)
        .build()
        .expect("building the execution RPC HTTP client")
}

/// Builds the upstream RPC client. On native targets outbound requests carry the
/// active span's trace context, so the upstream's own spans continue the caller's
/// trace rather than starting new ones, and they travel on a pooled transport.
#[cfg(not(target_arch = "wasm32"))]
fn build_rpc_client(rpc_url: Url) -> RpcClient {
    let is_local = guess_local_url(rpc_url.as_str());

    ClientBuilder::default()
        .layer(RetryBackoffLayer::new(100, 50, 300))
        .layer(super::trace::TraceInjectLayer)
        .transport(Http::with_client(build_http_client(), rpc_url), is_local)
}

/// Builds the upstream RPC client. The browser owns the connection pool, so wasm
/// keeps alloy's default transport.
#[cfg(target_arch = "wasm32")]
fn build_rpc_client(rpc_url: Url) -> RpcClient {
    ClientBuilder::default()
        .layer(RetryBackoffLayer::new(100, 50, 300))
        .http(rpc_url)
}

impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> ExecutionProvider<N>
    for RpcExecutionProvider<N, B, H>
{
}

impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>>
    RpcExecutionProvider<N, B, H>
{
    pub fn new(rpc_url: Url, block_provider: B) -> RpcExecutionProvider<N, B, ()> {
        let client = build_rpc_client(rpc_url);

        let provider = ProviderBuilder::<_, _, N>::default().connect_client(client);

        RpcExecutionProvider {
            provider,
            block_provider,
            historical_provider: None,
        }
    }

    pub fn with_historical_provider(
        rpc_url: Url,
        block_provider: B,
        historical_provider: H,
    ) -> Self {
        let client = build_rpc_client(rpc_url);

        let provider = ProviderBuilder::<_, _, N>::default().connect_client(client);

        Self {
            provider,
            block_provider,
            historical_provider: Some(historical_provider),
        }
    }

    async fn verify_logs(&self, logs: &[Log]) -> Result<()> {
        // get latest block
        let latest = self
            .get_block(BlockId::Number(BlockNumberOrTag::Latest), false)
            .await?
            .ok_or(eyre!("block not found"))?
            .header()
            .number();

        // Collect all (unique) block numbers
        let block_nums = logs
            .iter()
            .filter_map(|log| log.block_number.filter(|number| *number <= latest))
            .collect::<HashSet<u64>>();

        // Collect all (proven) tx receipts for all block numbers
        let blocks_receipts_fut = block_nums
            .into_iter()
            .map(|block_num| async move { self.get_block_receipts(block_num.into()).await });

        let blocks_receipts = try_join_all(blocks_receipts_fut).await?;
        let receipts = blocks_receipts
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>();

        // Map tx hashes to encoded logs
        let receipts_logs_encoded = receipts
            .into_iter()
            .filter_map(|receipt| {
                let logs = N::receipt_logs(&receipt);
                if logs.is_empty() {
                    None
                } else {
                    let tx_hash = logs[0].transaction_hash.unwrap();
                    let encoded_logs = logs
                        .iter()
                        .map(|l| rlp::encode(&l.inner))
                        .collect::<Vec<_>>();
                    Some((tx_hash, encoded_logs))
                }
            })
            .collect::<HashMap<_, _>>();

        for log in logs {
            // Check if the receipt contains the desired log
            // Encoding logs for comparison
            let tx_hash = log.transaction_hash.unwrap();
            let log_encoded = rlp::encode(&log.inner);
            let receipt_logs_encoded = receipts_logs_encoded.get(&tx_hash).unwrap();

            if !receipt_logs_encoded.contains(&log_encoded) {
                return Err(ExecutionError::MissingLog(
                    tx_hash,
                    U256::from(log.log_index.unwrap()),
                )
                .into());
            }
        }
        Ok(())
    }

    async fn resolve_block_number(&self, block: Option<BlockNumberOrTag>) -> Result<u64> {
        match block {
            Some(BlockNumberOrTag::Latest) | None => {
                let number = self
                    .get_block(BlockId::Number(BlockNumberOrTag::Latest), false)
                    .await?
                    .ok_or(eyre!("block not found"))?
                    .header()
                    .number();

                Ok(number)
            }
            Some(BlockNumberOrTag::Finalized) => {
                let number = self
                    .get_block(BlockId::Number(BlockNumberOrTag::Finalized), false)
                    .await?
                    .ok_or(eyre!("block not found"))?
                    .header()
                    .number();

                Ok(number)
            }
            Some(BlockNumberOrTag::Number(number)) => Ok(number),
            _ => Err(eyre!("block not found")),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> AccountProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    // An ACL check drives one of these per account it touches, and each fetches a
    // proof plus, on a first sighting, the code. Naming them individually is what
    // separates proof fetching from proof verification in a request's timeline.
    #[cfg_attr(
        not(target_arch = "wasm32"),
        tracing::instrument(
            name = "helios.get_account",
            skip_all,
            fields(address = %address, slots = slots.len(), with_code)
        )
    )]
    async fn get_account(
        &self,
        address: Address,
        slots: &[B256],
        with_code: bool,
        block_id: BlockId,
    ) -> Result<Account> {
        // get_account showed 90-170ms of self-time against only ~17ms of
        // upstream RPC underneath it, and the span had no children besides the
        // proof fetch -- so the majority of an ACL check was unattributed.
        // Each step below is spanned so that time resolves into block
        // resolution, proof fetching, verification CPU and the optional code
        // fetch, rather than one opaque number.
        use tracing::Instrument;

        let block = self
            .get_block(block_id, false)
            .instrument(tracing::info_span!("helios.get_block"))
            .await?
            .ok_or(eyre!("block not found"))?;

        // Proof and code are fetched CONCURRENTLY, not one after the other.
        //
        // Awaiting the proof first and only then the code made every account a
        // chain of two WAN round trips, and because the accounts themselves run
        // in parallel that showed up as two distinct waves in a trace: the
        // proofs all starting at t+0 and finishing by t+40, then the code
        // fetches starting at t+40 and running to t+117. The second wave was
        // ~76ms of a ~226ms read, and it existed only because of the await
        // order.
        //
        // get_code_at needs nothing from the proof. Only two things do: the
        // DECISION to fetch (skip when code_hash is empty) and the
        // VERIFICATION. So the fetch is fired speculatively alongside the
        // proof, and once the proof lands the result is either verified or
        // thrown away.
        //
        // Cost: one wasted eth_getCode for every EOA, which have no code. That
        // is a request we would not otherwise make, traded for removing a
        // serial round trip from every contract account.
        //
        // Safety: unchanged. The speculative body is never used without
        // verify_code_hash_proof against the proof we just verified against the
        // consensus state root, and it is discarded outright when the account
        // turns out to have no code.
        let (proof, speculative_code) = tokio::join!(
            async {
                self.provider
                    .get_proof(address, slots.to_vec())
                    .block_id(block.header().hash().into())
                    .await
            }
            .instrument(tracing::info_span!("helios.get_proof", slots = slots.len())),
            async {
                if with_code {
                    Some(self.provider.get_code_at(address).await)
                } else {
                    None
                }
            }
            .instrument(tracing::info_span!("helios.get_code", speculative = true)),
        );
        let proof = proof?;

        // Synchronous keccak/RLP over the trie path. Entered rather than
        // instrumented because there is no await inside.
        {
            let _v = tracing::info_span!("helios.verify_proof").entered();
            verify_account_proof(&proof, block.header().state_root())?;
            verify_storage_proof(&proof)?;
        }

        let code = if with_code {
            if proof.code_hash == KECCAK_EMPTY || proof.code_hash == B256::ZERO {
                // No code at this address: the speculative fetch was wasted.
                // Drop it rather than let an empty/garbage body reach the EVM.
                Some(Bytes::new())
            } else {
                // Only surface a fetch error here, on the path that actually
                // needs the code -- an error on an account that turns out to be
                // an EOA must not fail the request.
                let code = match speculative_code {
                    Some(result) => result?,
                    // with_code was true, so the future above always produced
                    // Some. Kept explicit rather than unwrap so a future change
                    // to that branch fails loudly instead of panicking.
                    None => async { self.provider.get_code_at(address).await }
                        .instrument(tracing::info_span!("helios.get_code", speculative = false))
                        .await?,
                };
                let _v = tracing::info_span!("helios.verify_code").entered();
                verify_code_hash_proof(&proof, &code)?;
                Some(code)
            }
        } else {
            None
        };

        Ok(Account {
            account: TrieAccount {
                nonce: proof.nonce,
                balance: proof.balance,
                storage_root: proof.storage_hash,
                code_hash: proof.code_hash,
            },
            code,
            account_proof: proof.account_proof,
            storage_proof: proof.storage_proof,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> BlockProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>> {
        // 1. Try block cache first
        if let Some(block) = self.block_provider.get_block(block_id, full_tx).await? {
            return Ok(Some(block));
        }

        // 2. Try historical provider if available and only for block numbers or hashes (not tags)
        if let Some(historical) = &self.historical_provider {
            if super::utils::should_use_historical_provider(&block_id) {
                if let Some(block) = historical
                    .get_historical_block(block_id, full_tx, self)
                    .await?
                {
                    // Note: Do NOT cache historical blocks to avoid interfering with consistency detection
                    return Ok(Some(block));
                }
            }
        }

        Ok(None)
    }

    async fn get_untrusted_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<<N>::BlockResponse>> {
        if full_tx {
            Ok(self.provider.get_block(block_id).full().await?)
        } else {
            Ok(self.provider.get_block(block_id).hashes().await?)
        }
    }

    async fn push_block(&self, block: N::BlockResponse, block_id: BlockId) {
        self.block_provider.push_block(block, block_id).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> TransactionProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_transaction(&self, hash: B256) -> Result<Option<N::TransactionResponse>> {
        let tx = self.provider.get_transaction_by_hash(hash).await?;
        if let Some(tx) = tx {
            let block_hash = tx.block_hash().ok_or(eyre!("block not found"))?;
            let block = self.get_block(block_hash.into(), true).await?;

            let block = block.ok_or(eyre!("block not found"))?;
            let txs = block.transactions().clone().into_transactions_vec();
            Ok(txs.iter().find(|v| v.tx_hash() == tx.tx_hash()).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_transaction_by_location(
        &self,
        block_id: BlockId,
        index: u64,
    ) -> Result<Option<N::TransactionResponse>> {
        let block = self.get_block(block_id, true).await?;

        let block = block.ok_or(eyre!("block not found"))?;
        let txs = block.transactions().clone().into_transactions_vec();
        Ok(txs.get(index as usize).cloned())
    }

    async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<B256> {
        let tx = self.provider.send_raw_transaction(bytes).await?;
        Ok(*tx.tx_hash())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> ReceiptProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_receipt(&self, hash: B256) -> Result<Option<N::ReceiptResponse>> {
        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await?
            .ok_or(eyre!("receipt not found"))?;

        let block_hash = receipt.block_hash().ok_or(eyre!("block not found"))?;
        let block = self
            .get_block(block_hash.into(), false)
            .await?
            .ok_or(eyre!("block not found"))?;

        let receipts = self
            .provider
            .get_block_receipts(block_hash.into())
            .await?
            .ok_or(eyre!("block not found"))?;

        verify_block_receipts::<N>(&receipts, &block)?;
        Ok(receipts
            .iter()
            .find(|receipt| receipt.transaction_hash() == hash)
            .cloned())
    }

    async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<N::ReceiptResponse>>> {
        let Some(block) = self.get_block(block_id, false).await? else {
            return Ok(None);
        };

        let receipts = self
            .provider
            .get_block_receipts(block.header().hash().into())
            .await?
            .ok_or(eyre!("receipt fetch failed"))?;

        verify_block_receipts::<N>(&receipts, &block)?;
        Ok(Some(receipts))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> LogProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        let block_option = match filter.block_option {
            FilterBlockOption::Range {
                from_block,
                to_block,
            } => {
                let from = self.resolve_block_number(from_block).await?;
                let to = self.resolve_block_number(to_block).await?;
                FilterBlockOption::Range {
                    from_block: Some(BlockNumberOrTag::Number(from)),
                    to_block: Some(BlockNumberOrTag::Number(to)),
                }
            }
            FilterBlockOption::AtBlockHash(hash) => FilterBlockOption::AtBlockHash(hash),
        };

        let mut filter = filter.clone();
        filter.block_option = block_option;

        let logs = self.provider.get_logs(&filter).await?;
        self.verify_logs(&logs).await?;
        ensure_logs_match_filter(&logs, &filter)?;
        Ok(logs)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>> ExecutionHintProvider<N>
    for RpcExecutionProvider<N, B, H>
{
    async fn get_execution_hint(
        &self,
        tx: &N::TransactionRequest,
        _validate: bool,
        block_id: BlockId,
    ) -> Result<HashMap<Address, Account>> {
        // Resolving the touched-account set is now a separate step so a caching
        // wrapper can reuse it and fetch the accounts through its own cache. The
        // behaviour here is unchanged: same list, same parallel chunked fetch.
        let list = self
            .resolve_execution_access_list(tx, block_id)
            .await?
            .unwrap_or_default();

        let mut account_map = HashMap::new();
        for chunk in list.chunks(PARALLEL_QUERY_BATCH_SIZE) {
            let account_chunk_futs = chunk.iter().map(|account| {
                let account_fut =
                    self.get_account(account.address, &account.storage_keys, true, block_id);
                async move { (account.address, account_fut.await) }
            });

            let account_chunk = join_all(account_chunk_futs).await;

            for (address, value) in account_chunk {
                let account = value?;
                account_map.insert(address, account);
            }
        }

        Ok(account_map)
    }

    async fn get_execution_access_list(
        &self,
        tx: &N::TransactionRequest,
        block_id: BlockId,
    ) -> Result<Option<Vec<AccessListItem>>> {
        self.resolve_execution_access_list(tx, block_id).await
    }
}

impl<N: NetworkSpec, B: BlockProvider<N>, H: HistoricalBlockProvider<N>>
    RpcExecutionProvider<N, B, H>
{
    /// The access list for `tx`, plus the three accounts the EVM always touches but
    /// which `eth_createAccessList` does not report: the sender, the recipient and
    /// the block's beneficiary.
    ///
    /// Lifted out of `get_execution_hint` verbatim so the caching wrapper can ask
    /// "which accounts?" without also being handed "and here is their state,
    /// fetched uncached".
    async fn resolve_execution_access_list(
        &self,
        tx: &N::TransactionRequest,
        block_id: BlockId,
    ) -> Result<Option<Vec<AccessListItem>>> {
        let block = self
            .get_block(block_id, false)
            .await?
            .ok_or(eyre!("block not found"))?;

        let mut list = self
            .provider
            .create_access_list(tx)
            .block_id(block_id)
            .await?
            .access_list
            .0;

        let from_access_entry = AccessListItem {
            address: tx.from().unwrap_or_default(),
            storage_keys: Vec::default(),
        };
        let to_access_entry = AccessListItem {
            address: tx.to().unwrap_or_default(),
            storage_keys: Vec::default(),
        };
        let producer_access_entry = AccessListItem {
            address: block.header().beneficiary(),
            storage_keys: Vec::default(),
        };

        let mut list_addresses = list.iter().map(|elem| elem.address).collect::<HashSet<_>>();

        if list_addresses.insert(from_access_entry.address) {
            list.push(from_access_entry)
        }
        if list_addresses.insert(to_access_entry.address) {
            list.push(to_access_entry)
        }
        if list_addresses.insert(producer_access_entry.address) {
            list.push(producer_access_entry)
        }

        Ok(Some(list))
    }
}
