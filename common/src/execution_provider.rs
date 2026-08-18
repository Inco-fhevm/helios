use std::collections::HashMap;

use alloy::{
    eips::BlockId,
    primitives::{Address, B256},
    rpc::types::{AccessListItem, Filter, Log},
};
use async_trait::async_trait;
use eyre::Result;

use crate::{network_spec::NetworkSpec, types::Account};

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait ExecutionProvider<N: NetworkSpec>:
    AccountProvider<N>
    + BlockProvider<N>
    + TransactionProvider<N>
    + ReceiptProvider<N>
    + LogProvider<N>
    + ExecutionHintProvider<N>
    + Send
    + Sync
    + 'static
{
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AccountProvider<N: NetworkSpec> {
    async fn get_account(
        &self,
        address: Address,
        slots: &[B256],
        with_code: bool,
        block_id: BlockId,
    ) -> Result<Account>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait BlockProvider<N: NetworkSpec>: Send + Sync + 'static {
    async fn push_block(&self, block: N::BlockResponse, block_id: BlockId);
    async fn get_block(&self, block_id: BlockId, full_tx: bool)
        -> Result<Option<N::BlockResponse>>;
    async fn get_untrusted_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait TransactionProvider<N: NetworkSpec> {
    async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<B256>;
    async fn get_transaction(&self, hash: B256) -> Result<Option<N::TransactionResponse>>;
    async fn get_transaction_by_location(
        &self,
        block_id: BlockId,
        index: u64,
    ) -> Result<Option<N::TransactionResponse>>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait ReceiptProvider<N: NetworkSpec> {
    async fn get_receipt(&self, hash: B256) -> Result<Option<N::ReceiptResponse>>;
    async fn get_block_receipts(&self, block: BlockId) -> Result<Option<Vec<N::ReceiptResponse>>>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait LogProvider<N: NetworkSpec> {
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait ExecutionHintProvider<N: NetworkSpec> {
    async fn get_execution_hint(
        &self,
        call: &N::TransactionRequest,
        validate: bool,
        block_id: BlockId,
    ) -> Result<HashMap<Address, Account>>;

    /// The accounts a call will touch, WITHOUT fetching their state.
    ///
    /// Exists so a caching layer can decide what to fetch rather than handing the
    /// whole job to the inner provider. The RPC provider's `get_execution_hint`
    /// resolves an access list and then fans out one `get_account` per entry; when
    /// that provider is wrapped for caching, those fan-out calls land on the INNER
    /// provider and bypass the cache. Every ACL check therefore re-proved the same
    /// accounts -- measured at 12 state calls per read across only 4 distinct
    /// addresses, identical on every request, which pinned read throughput at
    /// ~160/s while reth served each proof in 0.70ms and sat idle.
    ///
    /// `None` means "I assemble hints myself, do not try to be clever": that is the
    /// verifiable-api provider, where the fan-out happens server-side next to the
    /// node and there is nothing local to cache. Defaulting to `None` keeps every
    /// existing provider's behaviour byte-for-byte until it opts in.
    async fn get_execution_access_list(
        &self,
        _call: &N::TransactionRequest,
        _block_id: BlockId,
    ) -> Result<Option<Vec<AccessListItem>>> {
        Ok(None)
    }
}
