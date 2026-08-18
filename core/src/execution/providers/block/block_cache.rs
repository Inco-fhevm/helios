use std::collections::BTreeMap;
use std::sync::Arc;

use alloy::consensus::BlockHeader;
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::network::{primitives::HeaderResponse, BlockResponse};
use alloy::primitives::B256;
use alloy::rpc::types::BlockTransactions;
use async_trait::async_trait;

use eyre::Result;
use helios_common::{execution_provider::BlockProvider, network_spec::NetworkSpec};
use tokio::sync::RwLock;
use tracing::warn;

use crate::execution::constants::MAX_STATE_HISTORY_LENGTH;

pub struct BlockCache<N: NetworkSpec> {
    latest: Arc<RwLock<Option<N::BlockResponse>>>,
    finalized: Arc<RwLock<Option<N::BlockResponse>>>,
    blocks: Arc<RwLock<BTreeMap<u64, N::BlockResponse>>>,
    hashes: Arc<RwLock<BTreeMap<B256, u64>>>,
    size: usize,
}

impl<N: NetworkSpec> BlockCache<N> {
    pub fn new() -> Self {
        Self {
            latest: Arc::default(),
            finalized: Arc::default(),
            blocks: Arc::default(),
            hashes: Arc::default(),
            size: MAX_STATE_HISTORY_LENGTH,
        }
    }

    /// Drop every non-finalized block at or above `from_number`.
    ///
    /// This is the targeted form of [`Self::clear`], used when a reorg is
    /// actually observed. Only blocks from the divergence point upward can be
    /// affected by a reorg; everything below it -- and anything finalized --
    /// is still valid, so wiping those throws away good work for nothing.
    async fn evict_from(&self, from_number: u64) {
        let finalized_number = self
            .finalized
            .read()
            .await
            .as_ref()
            .map(|b| b.header().number());

        let mut blocks = self.blocks.write().await;
        let mut hashes = self.hashes.write().await;

        let doomed: Vec<u64> = blocks
            .range(from_number..)
            .filter(|(number, _)| Some(**number) != finalized_number)
            .map(|(number, _)| *number)
            .collect();

        for number in doomed {
            if let Some(block) = blocks.remove(&number) {
                hashes.remove(&block.header().hash());
            }
        }

        // The latest pointer may have referred to a block we just dropped.
        let latest_gone = self
            .latest
            .read()
            .await
            .as_ref()
            .is_some_and(|b| b.header().number() >= from_number);
        if latest_gone {
            *self.latest.write().await = None;
        }
    }

    /// Clear all cached blocks except the finalized block
    /// Finalized blocks are preserved since they cannot be reorganized
    #[allow(dead_code)]
    async fn clear(&self) {
        let finalized_block = self.finalized.read().await.clone();

        self.blocks.write().await.clear();
        self.hashes.write().await.clear();
        *self.latest.write().await = None;

        // Re-insert finalized block if it exists
        if let Some(finalized) = finalized_block {
            let block_number = finalized.header().number();
            let block_hash = finalized.header().hash();

            self.blocks.write().await.insert(block_number, finalized);
            self.hashes.write().await.insert(block_hash, block_number);
        }
    }
}

impl<N: NetworkSpec> Default for BlockCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<N: NetworkSpec> BlockProvider<N> for BlockCache<N> {
    async fn get_block(
        &self,
        block_id: BlockId,
        full_tx: bool,
    ) -> Result<Option<N::BlockResponse>> {
        let block = match block_id {
            BlockId::Number(tag) => match tag {
                BlockNumberOrTag::Latest => self.latest.read().await.clone(),
                BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => {
                    self.finalized.read().await.clone()
                }
                BlockNumberOrTag::Number(number) => self.blocks.read().await.get(&number).cloned(),
                BlockNumberOrTag::Pending | BlockNumberOrTag::Earliest => None,
            },
            BlockId::Hash(hash) => {
                let hash: B256 = hash.into();
                if let Some(number) = self.hashes.read().await.get(&hash) {
                    self.blocks.read().await.get(number).cloned()
                } else {
                    None
                }
            }
        };

        if !full_tx {
            if let Some(mut block) = block {
                *block.transactions_mut() =
                    BlockTransactions::Hashes(block.transactions().hashes().collect());

                Ok(Some(block))
            } else {
                Ok(None)
            }
        } else {
            Ok(block)
        }
    }

    async fn get_untrusted_block(
        &self,
        _block_id: BlockId,
        _full_tx: bool,
    ) -> Result<Option<<N>::BlockResponse>> {
        Ok(None)
    }

    async fn push_block(&self, block: N::BlockResponse, block_id: BlockId) {
        let block_number = block.header().number();
        let block_hash = block.header().hash();
        let parent_hash = block.header().parent_hash();

        // Look for POSITIVE evidence that the chain diverged from what we hold.
        //
        // Only two things prove divergence:
        //   1. we already hold a different block at this same height, or
        //   2. we hold the parent height, and its hash is not this block's parent.
        //
        // A missing parent proves nothing. It happens routinely: concurrent
        // callers ask about scattered heights, so a request for N can land
        // before one for N-1, and the size limit evicts old entries from the
        // bottom. Treating that as a reorg and clearing the cache was
        // self-amplifying -- the wipe left the cache empty, so the next block
        // also found no parent and wiped again. Measured on devnet: 21% of
        // getExecutionHint requests triggered a wipe (62-65 per ~300),
        // unchanged across 1 replica, 3 replicas, and session affinity, which
        // is what kept refetching everything and producing the ACL latency tail.
        let divergence_at = if block_id.is_finalized() || block_number == 0 {
            None
        } else {
            let blocks = self.blocks.read().await;

            if let Some(existing) = blocks.get(&block_number) {
                // Same height, different block: the chain moved under us.
                (existing.header().hash() != block_hash).then_some(block_number)
            } else if let Some(parent_block) = blocks.get(&(block_number - 1)) {
                // We hold the parent height and it does not match: divergence
                // is at the parent, so the parent itself must go too.
                (parent_block.header().hash() != parent_hash).then_some(block_number - 1)
            } else {
                // Gap. Not evidence of anything -- just insert alongside.
                None
            }
        };

        if let Some(from) = divergence_at {
            warn!(
                block_number,
                evict_from = from,
                "reorg detected: evicting divergent blocks"
            );
            self.evict_from(from).await;
        }

        // Update latest/finalized references
        if let BlockId::Number(tag) = block_id {
            match tag {
                BlockNumberOrTag::Latest => *self.latest.write().await = Some(block.clone()),
                BlockNumberOrTag::Finalized => *self.finalized.write().await = Some(block.clone()),
                _ => (),
            }
        }

        // Insert the new block
        self.hashes.write().await.insert(block_hash, block_number);

        self.blocks.write().await.insert(block_number, block);

        // Maintain cache size limit
        while self.blocks.read().await.len() > self.size {
            let (num, old_block_hash) = {
                let blocks = self.blocks.read().await;
                if let Some((num, block)) = blocks.first_key_value() {
                    (*num, block.header().hash())
                } else {
                    break;
                }
            };

            self.blocks.write().await.remove(&num).unwrap();
            self.hashes.write().await.remove(&old_block_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::network::Network;
    use alloy::primitives::{B64, B256};
    use helios_ethereum::spec::Ethereum;

    /// Clone a real block from testdata and re-stamp its identity. `salt` lets a
    /// test produce two different blocks at the same height, which is what a
    /// reorg looks like on the wire.
    fn block(number: u64, parent: B256, salt: u8) -> <Ethereum as Network>::BlockResponse {
        let mut b = helios_test_utils::rpc_block();
        b.header.inner.number = number;
        b.header.inner.parent_hash = parent;
        b.header.inner.nonce = B64::with_last_byte(salt);
        b.header.hash = b.header.inner.hash_slow();
        b
    }

    fn at(n: u64) -> BlockId {
        BlockId::Number(BlockNumberOrTag::Number(n))
    }

    async fn numbers(cache: &BlockCache<Ethereum>) -> Vec<u64> {
        cache.blocks.read().await.keys().copied().collect()
    }

    /// A contiguous chain must never evict anything.
    #[tokio::test]
    async fn contiguous_chain_keeps_everything() {
        let cache = BlockCache::<Ethereum>::new();
        let b100 = block(100, B256::ZERO, 1);
        let b101 = block(101, b100.header.hash, 1);
        let b102 = block(102, b101.header.hash, 1);
        cache.push_block(b100, at(100)).await;
        cache.push_block(b101, at(101)).await;
        cache.push_block(b102, at(102)).await;
        assert_eq!(numbers(&cache).await, vec![100, 101, 102]);
    }

    /// THE REGRESSION THIS FIX TARGETS. A block whose parent is simply not
    /// cached is a gap, not a reorg, and must not discard unrelated entries.
    /// Previously this wiped the cache, and because the wipe emptied it the
    /// next insert wiped again -- 21% of production requests.
    #[tokio::test]
    async fn gap_does_not_wipe_the_cache() {
        let cache = BlockCache::<Ethereum>::new();
        cache.push_block(block(100, B256::ZERO, 1), at(100)).await;
        // Jump ahead; block 199 was never fetched.
        cache
            .push_block(block(200, B256::repeat_byte(0xAB), 1), at(200))
            .await;
        assert_eq!(
            numbers(&cache).await,
            vec![100, 200],
            "a missing parent must not evict unrelated blocks"
        );
    }

    /// Out-of-order arrival is the common concurrent case: N lands before N-1.
    #[tokio::test]
    async fn out_of_order_arrival_keeps_both() {
        let cache = BlockCache::<Ethereum>::new();
        let b100 = block(100, B256::ZERO, 1);
        let b101 = block(101, b100.header.hash, 1);
        cache.push_block(b101, at(101)).await;
        cache.push_block(b100, at(100)).await;
        assert_eq!(numbers(&cache).await, vec![100, 101]);
    }

    /// A different block at a height we already hold IS a reorg: that height
    /// and everything above must go, lower blocks must survive.
    #[tokio::test]
    async fn reorg_at_same_height_evicts_from_there_up() {
        let cache = BlockCache::<Ethereum>::new();
        let b100 = block(100, B256::ZERO, 1);
        let b101 = block(101, b100.header.hash, 1);
        let b102 = block(102, b101.header.hash, 1);
        cache.push_block(b100.clone(), at(100)).await;
        cache.push_block(b101.clone(), at(101)).await;
        cache.push_block(b102, at(102)).await;

        let b101b = block(101, b100.header.hash, 2);
        assert_ne!(b101.header.hash, b101b.header.hash);
        cache.push_block(b101b.clone(), at(101)).await;

        assert_eq!(
            numbers(&cache).await,
            vec![100, 101],
            "102 was built on the abandoned 101 and must be dropped"
        );
        assert_eq!(
            cache.blocks.read().await.get(&101).unwrap().header.hash,
            b101b.header.hash,
            "the surviving 101 must be the new one"
        );
    }

    /// A parent we hold whose hash does not match means the parent is on the
    /// abandoned branch, so eviction starts at the parent.
    #[tokio::test]
    async fn mismatched_parent_evicts_the_parent_too() {
        let cache = BlockCache::<Ethereum>::new();
        let b100 = block(100, B256::ZERO, 1);
        let b101 = block(101, b100.header.hash, 1);
        cache.push_block(b100, at(100)).await;
        cache.push_block(b101, at(101)).await;
        cache
            .push_block(block(102, B256::repeat_byte(0xCD), 1), at(102))
            .await;
        assert_eq!(
            numbers(&cache).await,
            vec![100, 102],
            "the divergent 101 must go; 100 is below the divergence and stays"
        );
    }

    /// Evicted blocks must not remain addressable by hash.
    #[tokio::test]
    async fn evicted_blocks_are_unreachable_by_hash() {
        let cache = BlockCache::<Ethereum>::new();
        let b100 = block(100, B256::ZERO, 1);
        let b101 = block(101, b100.header.hash, 1);
        cache.push_block(b100.clone(), at(100)).await;
        cache.push_block(b101.clone(), at(101)).await;
        cache.push_block(block(101, b100.header.hash, 2), at(101)).await;
        assert!(
            !cache.hashes.read().await.contains_key(&b101.header.hash),
            "the abandoned block must not remain addressable by hash"
        );
    }
}
