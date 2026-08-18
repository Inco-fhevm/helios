use std::{collections::HashMap, sync::Arc};

use alloy::{
    eips::BlockId,
    network::{primitives::HeaderResponse, BlockResponse},
    primitives::{Address, B256},
    rpc::types::{Filter, Log},
};
use async_trait::async_trait;
use eyre::{eyre, Result};
use futures::future::join_all;

use helios_common::{
    execution_provider::{
        AccountProvider, BlockProvider, ExecutionHintProvider, ExecutionProvider, LogProvider,
        ReceiptProvider, TransactionProvider,
    },
    network_spec::NetworkSpec,
    types::Account,
};

use crate::execution::constants::PARALLEL_QUERY_BATCH_SIZE;

use super::Cache;

pub struct CachingProvider<P> {
    inner: P,
    cache: Arc<Cache>,
}

impl<P> CachingProvider<P> {
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cache: Arc::new(Cache::new()),
        }
    }
}

impl<N, P> ExecutionProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N, P> AccountProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
    async fn get_account(
        &self,
        address: Address,
        slots: &[B256],
        with_code: bool,
        block_id: BlockId,
    ) -> Result<Account> {
        let block_hash = match block_id {
            BlockId::Hash(hash) => hash.into(),
            _ => self
                .inner
                .get_block(block_id, false)
                .await?
                .ok_or_else(|| eyre!("block not found"))?
                .header()
                .hash(),
        };

        let cached = self.cache.get_account(address, slots, block_hash);

        match cached {
            None => {
                if with_code {
                    if let Some((cached_code_hash, cached_code)) =
                        self.cache.get_code_optimistically(address)
                    {
                        let fetched = self
                            .inner
                            .get_account(address, slots, false, block_hash.into())
                            .await?;
                        if fetched.account.code_hash == cached_code_hash {
                            let mut account = fetched;
                            account.code = Some(cached_code);
                            self.cache.insert_account(address, &account, block_hash);
                            return Ok(account);
                        }
                    }
                }
                let fetched = self
                    .inner
                    .get_account(address, slots, with_code, block_hash.into())
                    .await?;
                self.cache.insert_account(address, &fetched, block_hash);
                Ok(fetched)
            }
            Some((mut account, missing_slots)) => {
                let need_code = with_code && account.code.is_none();

                if !missing_slots.is_empty() || need_code {
                    let fetched = self
                        .inner
                        .get_account(address, &missing_slots, need_code, block_hash.into())
                        .await?;
                    self.cache.insert_account(address, &fetched, block_hash);

                    account.account = fetched.account;
                    account.account_proof = fetched.account_proof;
                    account.storage_proof.extend(fetched.storage_proof);
                    if let Some(code) = fetched.code {
                        account.code = Some(code);
                    }
                }

                Ok(account)
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N, P> BlockProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
    async fn push_block(&self, block: N::BlockResponse, block_id: BlockId) {
        self.inner.push_block(block, block_id).await
    }

    async fn get_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>> {
        self.inner.get_block(block_id, full_tx).await
    }

    async fn get_untrusted_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>> {
        self.inner.get_untrusted_block(block_id, full_tx).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N, P> TransactionProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
    async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<B256> {
        self.inner.send_raw_transaction(bytes).await
    }

    async fn get_transaction(&self, hash: B256) -> Result<Option<N::TransactionResponse>> {
        self.inner.get_transaction(hash).await
    }

    async fn get_transaction_by_location(
        &self,
        block_id: BlockId,
        index: u64,
    ) -> Result<Option<N::TransactionResponse>> {
        self.inner
            .get_transaction_by_location(block_id, index)
            .await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N, P> ReceiptProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
    async fn get_receipt(&self, hash: B256) -> Result<Option<N::ReceiptResponse>> {
        self.inner.get_receipt(hash).await
    }

    async fn get_block_receipts(&self, block: BlockId) -> Result<Option<Vec<N::ReceiptResponse>>> {
        self.inner.get_block_receipts(block).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N, P> LogProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        self.inner.get_logs(filter).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N, P> ExecutionHintProvider<N> for CachingProvider<P>
where
    N: NetworkSpec,
    P: ExecutionProvider<N>,
{
    async fn get_execution_hint(
        &self,
        call: &N::TransactionRequest,
        validate: bool,
        block_id: BlockId,
    ) -> Result<HashMap<Address, Account>> {
        // Ask the inner provider only WHICH accounts are needed, then fetch them
        // through `self.get_account` so the cache above is actually consulted.
        //
        // Delegating the whole call was the defect: the inner provider's fan-out
        // calls its OWN uncached `get_account`, so every ACL check re-proved the
        // same accounts at the same block. Measured: 12 state calls per read over
        // only 4 distinct addresses, identical on every request, 3682 RPC calls for
        // 200 concurrent reads, throughput pinned at ~160/s while reth answered
        // each proof in 0.70ms and sat idle. Proofs are valid per block and the
        // cache is keyed `(address, block_hash)`, so within one block the first
        // read pays the fetches and every later read pays nothing.
        //
        // `None` means the provider assembles hints itself (verifiable-api, which
        // fans out server-side next to the node); delegate unchanged there.
        let Some(list) = self.inner.get_execution_access_list(call, block_id).await? else {
            return self
                .inner
                .get_execution_hint(call, validate, block_id)
                .await;
        };

        let mut account_map = HashMap::new();
        for chunk in list.chunks(PARALLEL_QUERY_BATCH_SIZE) {
            let futs = chunk.iter().map(|item| {
                let fut = self.get_account(item.address, &item.storage_keys, true, block_id);
                async move { (item.address, fut.await) }
            });
            for (address, value) in join_all(futs).await {
                account_map.insert(address, value?);
            }
        }

        Ok(account_map)
    }
}
