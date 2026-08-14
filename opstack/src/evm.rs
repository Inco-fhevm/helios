use std::{collections::HashMap, marker::PhantomData, mem, sync::Arc};

use alloy::{
    consensus::BlockHeader,
    eips::{eip1898::RpcBlockHash, BlockId},
    network::TransactionBuilder,
    rpc::types::{state::StateOverride, Block, Header},
};
use eyre::Result;
use op_alloy_consensus::OpTxType;
use op_alloy_rpc_types::{OpTransactionRequest, Transaction};
use op_revm::{DefaultOp, OpBuilder, OpContext, OpHaltReason, OpSpecId, OpTransaction};
use revm::{
    context::{result::ExecutionResult, BlockEnv, CfgEnv, ContextTr, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::EmptyDB,
    primitives::{Address, Bytes, U256},
    Context, ExecuteEvm,
};
use tracing::debug;

use helios_common::{
    execution_provider::ExecutionProvider,
    fork_schedule::ForkSchedule,
    types::{Account, EvmError},
};
use helios_core::execution::errors::ExecutionError;
use helios_revm_utils::proof_db::ProofDB;

use crate::spec::OpStack;

pub struct OpStackEvm<E: ExecutionProvider<OpStack>> {
    execution: Arc<E>,
    chain_id: u64,
    block_id: BlockId,
    fork_schedule: ForkSchedule,
    phantom: PhantomData<OpStack>,
}

impl<E: ExecutionProvider<OpStack>> OpStackEvm<E> {
    pub fn new(
        execution: Arc<E>,
        chain_id: u64,
        fork_schedule: ForkSchedule,
        block_id: BlockId,
    ) -> Self {
        Self {
            execution,
            chain_id,
            block_id,
            fork_schedule,
            phantom: PhantomData,
        }
    }

    pub async fn transact_inner(
        &mut self,
        tx: &OpTransactionRequest,
        validate_tx: bool,
        state_overrides: Option<StateOverride>,
    ) -> Result<(ExecutionResult<OpHaltReason>, HashMap<Address, Account>), EvmError> {
        let block = self
            .execution
            .get_block(self.block_id, false)
            .await
            .map_err(|err| EvmError::Generic(err.to_string()))?
            .ok_or(ExecutionError::BlockNotFound(self.block_id))
            .map_err(|err| EvmError::Generic(err.to_string()))?;

        // Pin block to a specific hash for the entire EVM run.
        let pinned_block: RpcBlockHash = block.header.hash.into();

        let mut db = ProofDB::new(pinned_block, self.execution.clone(), state_overrides);
        // The result is deliberately inspected rather than dropped: a failed
        // prefetch leaves the cache empty and turns the loop below into one
        // upstream round trip per touched account, which is the difference
        // between one call and ten. Dropping it made that failure silent.
        let prefetch_t = std::time::Instant::now();
        let prefetch_res = db.state.prefetch_state(tx, validate_tx).await;
        let prefetch_ms = prefetch_t.elapsed().as_secs_f64() * 1000.0;
        let prefetch_ok = prefetch_res.is_ok();
        let prefetch_err = match prefetch_res {
            Ok(()) => String::new(),
            Err(e) => format!("{e}"),
        };

        // Track iterations for debugging
        let mut iteration: u32 = 0;
        // This loop is the whole cost of an execution hint, and until now it was
        // one opaque span: measured at 221ms with no way to see whether that is
        // many cheap fetches, one slow one, or EVM execution itself. Each fetch
        // and each replay is timed separately below and the totals are reported
        // at the end, so the 221ms resolves into counts and per-call durations.
        let mut fetch_total_ms = 0.0f64;
        let mut fetch_max_ms = 0.0f64;
        let mut fetches: u32 = 0;
        let mut replay_total_ms = 0.0f64;
        let loop_t = std::time::Instant::now();

        let tx_res = loop {
            iteration += 1;

            // Update state first if needed
            if db.state.needs_update() {
                debug!(
                    "evm cache miss (iteration {}): {:?}",
                    iteration,
                    db.state.access.as_ref().unwrap()
                );
                let access = format!("{:?}", db.state.access.as_ref().unwrap());
                let t = std::time::Instant::now();
                let res = {
                    use tracing::Instrument;
                    db.state
                        .update_state()
                        .instrument(tracing::info_span!(
                            "evm.state_fetch",
                            iteration,
                            access = %access
                        ))
                        .await
                };
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                fetch_total_ms += ms;
                fetches += 1;
                if ms > fetch_max_ms {
                    fetch_max_ms = ms;
                }
                res.map_err(|e| EvmError::Generic(e.to_string()))?;
            }

            // Create EVM after any async operations
            let context = self.get_context(tx, &block, validate_tx);

            // Execute in a scope to ensure EVM is dropped before any potential async operations
            let replay_t = std::time::Instant::now();
            let (result, needs_update) = {
                let mut evm = context.with_db(&mut db).build_op();
                let res = evm.replay();
                let needs_update = evm.0.db_mut().state.needs_update();
                (res, needs_update)
            };
            replay_total_ms += replay_t.elapsed().as_secs_f64() * 1000.0;

            if result.is_ok() || !needs_update {
                break result.map(|res| (res.result, mem::take(&mut db.state.accounts)));
            }
        };

        // Every millisecond of the loop is one of: waiting on an upstream fetch,
        // running the EVM, or neither (bookkeeping). Reported together so the
        // three are comparable without correlating spans.
        let loop_ms = loop_t.elapsed().as_secs_f64() * 1000.0;
        tracing::info!(
            iterations = iteration,
            fetches,
            fetch_total_ms,
            fetch_max_ms,
            replay_total_ms,
            loop_ms,
            other_ms = loop_ms - fetch_total_ms - replay_total_ms,
            prefetch_ms,
            prefetch_ok,
            prefetch_err = %prefetch_err,
            "evm transact loop"
        );

        tx_res.map_err(|err| EvmError::Generic(format!("generic: {err}")))
    }

    fn get_context(
        &self,
        tx: &OpTransactionRequest,
        block: &Block<Transaction>,
        validate_tx: bool,
    ) -> OpContext<EmptyDB> {
        let mut tx_env = Self::tx_env(tx);

        if <OpTxType as Into<u8>>::into(
            <OpTransactionRequest as TransactionBuilder<OpStack>>::output_tx_type(tx),
        ) == 0u8
        {
            tx_env.chain_id = None;
        } else {
            tx_env.chain_id = Some(self.chain_id);
        }

        let mut cfg = CfgEnv::default();
        cfg.spec = get_spec_id_for_block_timestamp(block.header.timestamp, &self.fork_schedule);
        cfg.chain_id = self.chain_id;
        cfg.disable_block_gas_limit = !validate_tx;
        cfg.disable_eip3607 = !validate_tx;
        cfg.disable_base_fee = !validate_tx;
        cfg.disable_nonce_check = !validate_tx;

        let mut op_tx_env = OpTransaction::new(tx_env);
        op_tx_env.enveloped_tx = Some(Bytes::new());

        Context::op()
            .with_tx(op_tx_env)
            .with_block(Self::block_env(block, &self.fork_schedule))
            .with_cfg(cfg)
    }

    fn tx_env(tx: &OpTransactionRequest) -> TxEnv {
        TxEnv {
            tx_type: <OpTransactionRequest as TransactionBuilder<OpStack>>::output_tx_type(tx)
                .into(),
            caller: <OpTransactionRequest as TransactionBuilder<OpStack>>::from(tx)
                .unwrap_or_default(),
            gas_limit: <OpTransactionRequest as TransactionBuilder<OpStack>>::gas_limit(tx)
                .unwrap_or(u64::MAX),
            gas_price: <OpTransactionRequest as TransactionBuilder<OpStack>>::gas_price(tx)
                .unwrap_or_default(),
            kind: <OpTransactionRequest as TransactionBuilder<OpStack>>::kind(tx)
                .unwrap_or_default(),
            value: <OpTransactionRequest as TransactionBuilder<OpStack>>::value(tx)
                .unwrap_or_default(),
            data: <OpTransactionRequest as TransactionBuilder<OpStack>>::input(tx)
                .unwrap_or_default()
                .clone(),
            nonce: <OpTransactionRequest as TransactionBuilder<OpStack>>::nonce(tx)
                .unwrap_or_default(),
            chain_id: <OpTransactionRequest as TransactionBuilder<OpStack>>::chain_id(tx),
            access_list: <OpTransactionRequest as TransactionBuilder<OpStack>>::access_list(tx)
                .cloned()
                .unwrap_or_default(),
            gas_priority_fee:
                <OpTransactionRequest as TransactionBuilder<OpStack>>::max_priority_fee_per_gas(tx),
            max_fee_per_blob_gas: 0,
            blob_hashes: tx
                .as_ref()
                .blob_versioned_hashes
                .as_ref()
                .map(|v| v.to_vec())
                .unwrap_or_default(),
            authorization_list: vec![],
        }
    }

    fn block_env(block: &Block<Transaction, Header>, fork_schedule: &ForkSchedule) -> BlockEnv {
        // Get blob base fee update fraction based on fork
        let blob_base_fee_update_fraction =
            fork_schedule.get_blob_base_fee_update_fraction(block.header.timestamp());

        let blob_excess_gas_and_price =
            Some(BlobExcessGasAndPrice::new(0, blob_base_fee_update_fraction));

        BlockEnv {
            number: U256::from(block.header.number()),
            beneficiary: block.header.beneficiary(),
            timestamp: U256::from(block.header.timestamp()),
            gas_limit: block.header.gas_limit(),
            basefee: block.header.base_fee_per_gas().unwrap_or(0_u64),
            difficulty: block.header.difficulty(),
            prevrandao: block.header.mix_hash(),
            blob_excess_gas_and_price,
        }
    }
}

pub fn get_spec_id_for_block_timestamp(timestamp: u64, fork_schedule: &ForkSchedule) -> OpSpecId {
    if timestamp >= fork_schedule.isthmus_timestamp {
        OpSpecId::ISTHMUS
    } else if timestamp >= fork_schedule.holocene_timestamp {
        OpSpecId::HOLOCENE
    } else if timestamp >= fork_schedule.granite_timestamp {
        OpSpecId::GRANITE
    } else if timestamp >= fork_schedule.fjord_timestamp {
        OpSpecId::FJORD
    } else if timestamp >= fork_schedule.ecotone_timestamp {
        OpSpecId::ECOTONE
    } else if timestamp >= fork_schedule.canyon_timestamp {
        OpSpecId::CANYON
    } else if timestamp >= fork_schedule.regolith_timestamp {
        OpSpecId::REGOLITH
    } else if timestamp >= fork_schedule.bedrock_timestamp {
        OpSpecId::BEDROCK
    } else {
        OpSpecId::default()
    }
}
