use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{state_update::ContractClassUpdate, BlockHash};
use pathfinder_common::{
    BlockCommitmentSignature, BlockCommitmentSignatureElem, BlockNumber, Chain, ClassHash,
};
use pathfinder_storage::{BlockId, Storage};
use primitive_types::H160;
use starknet_gateway_types::reply::state_update::{
    DeclaredSierraClass, DeployedContract, ReplacedClass, StorageDiff,
};
use starknet_gateway_types::reply::{GasPrices, Status};

use anyhow::Result;
use pathfinder_common::hash::{FeltHash, PoseidonHash};
use pathfinder_common::receipt::{ExecutionStatus, Receipt};
use pathfinder_common::ReceiptCommitment;
use pathfinder_crypto::hash::{poseidon_hash_many, PoseidonHasher};
use pathfinder_crypto::{Felt, MontFelt};
use pathfinder_merkle_tree::TransactionOrEventTree;
use sha3::Digest;

#[derive(Debug, Clone)]
struct ReorgConfig {
    pub reorg_at_block: BlockNumber,
    pub reorg_to_block: BlockNumber,
}

pub fn get_chain(tx: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<Chain> {
    use pathfinder_common::consts::{
        MAINNET_GENESIS_HASH, SEPOLIA_INTEGRATION_GENESIS_HASH, SEPOLIA_TESTNET_GENESIS_HASH,
    };

    let genesis_hash = tx
        .block_hash(BlockNumber::GENESIS.into())
        .unwrap()
        .context("Getting genesis hash")?;

    let chain = match genesis_hash {
        MAINNET_GENESIS_HASH => Chain::Mainnet,
        SEPOLIA_TESTNET_GENESIS_HASH => Chain::SepoliaTestnet,
        SEPOLIA_INTEGRATION_GENESIS_HASH => Chain::SepoliaIntegration,
        _other => Chain::Custom,
    };

    Ok(chain)
}

pub fn contract_addresses(chain: Chain) -> anyhow::Result<ContractAddresses> {
    fn parse(hex: &str) -> H160 {
        let slice: [u8; 20] = const_decoder::Decoder::Hex.decode(hex.as_bytes());
        H160::from(slice)
    }

    Ok(match chain {
        Chain::Mainnet => ContractAddresses {
            core: parse("c662c410C0ECf747543f5bA90660f6ABeBD9C8c4"),
            gps: parse("47312450B3Ac8b5b8e247a6bB6d523e7605bDb60"),
        },
        Chain::Custom => ContractAddresses {
            // Formerly also Goerli integration
            core: parse("d5c325D183C592C94998000C5e0EED9e6655c020"),
            gps: parse("8f97970aC5a9aa8D130d35146F5b59c4aef57963"),
        },
        Chain::SepoliaTestnet => ContractAddresses {
            core: parse("E2Bb56ee936fd6433DC0F6e7e3b8365C906AA057"),
            gps: parse("07ec0D28e50322Eb0C159B9090ecF3aeA8346DFe"),
        },
        Chain::SepoliaIntegration => ContractAddresses {
            core: parse("4737c0c1B4D5b1A687B42610DdabEE781152359c"),
            gps: parse("07ec0D28e50322Eb0C159B9090ecF3aeA8346DFe"),
        },
    })
}

/// Groups the Starknet contract addresses for a specific chain.
///
/// Getting addresses: <SEQUENCER_URL>/feeder_gateway/get_contract_addresses
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
}

#[tracing::instrument(level = "trace", skip(tx))]
pub fn resolve_block(
    tx: &pathfinder_storage::Transaction<'_>,
    block_id: BlockId,
) -> anyhow::Result<starknet_gateway_types::reply::Block> {
    let header = tx
        .block_header(block_id)
        .context("Fetching block header")?
        .context("Block header missing")?;

    let transactions_receipts = tx
        .transaction_data_for_block(header.number.into())
        .context("Reading transactions from database")?
        .context("Transaction data missing")?;

    let receipts = transactions_receipts
        .iter()
        .map(|(_, r, _)| r.clone())
        .collect::<Vec<_>>();

    let receipt_commitment = calculate_receipt_commitment(&receipts)?;

    let (transactions, transaction_receipts): (Vec<_>, Vec<_>) = transactions_receipts
        .into_iter()
        .map(|(tx, rx, ev)| (tx, (rx, ev)))
        .unzip();

    let block_status = tx
        .block_is_l1_accepted(header.number.into())
        .context("Querying block status")?;
    let block_status = if block_status {
        Status::AcceptedOnL1
    } else {
        Status::AcceptedOnL2
    };

    Ok(starknet_gateway_types::reply::Block {
        block_hash: header.hash,
        block_number: header.number,
        l1_gas_price: GasPrices {
            price_in_wei: header.eth_l1_gas_price,
            price_in_fri: header.strk_l1_gas_price,
        },
        l1_data_gas_price: GasPrices {
            price_in_wei: header.eth_l1_data_gas_price,
            price_in_fri: header.strk_l1_data_gas_price,
        },
        parent_block_hash: header.parent_hash,
        sequencer_address: Some(header.sequencer_address),
        state_commitment: header.state_commitment,
        status: block_status,
        timestamp: header.timestamp,
        transaction_receipts,
        transactions,
        starknet_version: header.starknet_version,
        l1_da_mode: header.l1_da_mode.into(),
        transaction_commitment: header.transaction_commitment,
        event_commitment: header.event_commitment,
        receipt_commitment: Some(receipt_commitment),
        state_diff_commitment: Some(header.state_diff_commitment),
        state_diff_length: Some(header.state_diff_length),
    })
}

#[tracing::instrument(level = "trace", skip(tx))]
pub fn resolve_signature(
    tx: &pathfinder_storage::Transaction<'_>,
    block_id: BlockId,
) -> anyhow::Result<starknet_gateway_types::reply::BlockSignature> {
    let header = tx
        .block_header(block_id)
        .context("Fetching block header")?
        .context("Block header missing")?;

    let signature = tx
        .signature(block_id)
        .context("Fetching signature")?
        // fall back to zero since we might have missing signatures in old DBs
        .unwrap_or(BlockCommitmentSignature {
            r: BlockCommitmentSignatureElem::ZERO,
            s: BlockCommitmentSignatureElem::ZERO,
        });

    Ok(starknet_gateway_types::reply::BlockSignature {
        block_hash: header.hash,
        signature: [signature.r, signature.s],
    })
}

#[tracing::instrument(level = "trace", skip(tx))]
pub fn resolve_state_update(
    tx: &pathfinder_storage::Transaction<'_>,
    block: BlockId,
    reorg_config: Option<ReorgConfig>,
    reorged: Arc<AtomicBool>,
) -> anyhow::Result<starknet_gateway_types::reply::StateUpdate> {
    let block = if let Some(reorg_config) = reorg_config {
        match block {
            BlockId::Number(block_number) => {
                if reorged.load(Ordering::Relaxed) {
                    // reorg is active
                    if block_number > reorg_config.reorg_to_block {
                        anyhow::bail!("Reorged block requested");
                    }
                    reorged.store(false, Ordering::Relaxed);
                } else {
                    // reorg should start at this block
                    if block_number > reorg_config.reorg_at_block {
                        tracing::warn!(%reorg_config.reorg_to_block, "Reorg");
                        reorged.store(true, Ordering::Relaxed);
                        anyhow::bail!("Reorg happened");
                    }
                }

                block
            }
            BlockId::Latest => {
                if reorged.load(Ordering::Relaxed) {
                    reorg_config.reorg_to_block.into()
                } else {
                    block
                }
            }
            _ => block,
        }
    } else {
        block
    };

    tx.state_update(block)
        .context("Fetching state update")?
        .context("State update missing")
        .map(storage_to_gateway)
}

#[tracing::instrument(level = "trace", skip(tx))]
pub fn resolve_class(
    tx: &pathfinder_storage::Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Vec<u8>> {
    let definition = tx
        .class_definition(class_hash)
        .context("Reading class definition from database")?
        .ok_or_else(|| anyhow::anyhow!("No such class found"))?;

    Ok(definition)
}

pub fn storage_to_gateway(
    state_update: pathfinder_common::StateUpdate,
) -> starknet_gateway_types::reply::StateUpdate {
    let mut storage_diffs = HashMap::new();
    let mut deployed_contracts = Vec::new();
    let mut nonces = HashMap::new();
    let mut replaced_classes = Vec::new();

    for (address, update) in state_update.contract_updates {
        if let Some(nonce) = update.nonce {
            nonces.insert(address, nonce);
        }

        match update.class {
            Some(ContractClassUpdate::Deploy(class_hash)) => {
                deployed_contracts.push(DeployedContract {
                    address,
                    class_hash,
                })
            }
            Some(ContractClassUpdate::Replace(class_hash)) => {
                replaced_classes.push(ReplacedClass {
                    address,
                    class_hash,
                })
            }
            None => {}
        }

        let storage = update
            .storage
            .into_iter()
            .map(|(key, value)| StorageDiff { key, value })
            .collect();

        storage_diffs.insert(address, storage);
    }

    for (address, update) in state_update.system_contract_updates {
        let storage = update
            .storage
            .into_iter()
            .map(|(key, value)| StorageDiff { key, value })
            .collect();

        storage_diffs.insert(address, storage);
    }

    let declared_classes = state_update
        .declared_sierra_classes
        .into_iter()
        .map(|(class_hash, compiled_class_hash)| DeclaredSierraClass {
            class_hash,
            compiled_class_hash,
        })
        .collect();

    let state_diff = starknet_gateway_types::reply::state_update::StateDiff {
        storage_diffs,
        deployed_contracts,
        old_declared_contracts: state_update.declared_cairo_classes,
        declared_classes,
        nonces,
        replaced_classes,
    };

    starknet_gateway_types::reply::StateUpdate {
        block_hash: state_update.block_hash,
        new_root: state_update.state_commitment,
        old_root: state_update.parent_state_commitment,
        state_diff,
    }
}

pub fn calculate_receipt_commitment(receipts: &[Receipt]) -> Result<ReceiptCommitment> {
    use rayon::prelude::*;

    let hashes = receipts
        .par_iter()
        .map(|receipt| {
            poseidon_hash_many(&[
                receipt.transaction_hash.0.into(),
                receipt.actual_fee.0.into(),
                // Calculate hash of messages sent.
                {
                    let mut hasher = PoseidonHasher::new();
                    hasher.write((receipt.l2_to_l1_messages.len() as u64).into());
                    for msg in &receipt.l2_to_l1_messages {
                        hasher.write(msg.from_address.0.into());
                        hasher.write(msg.to_address.0.into());
                        hasher.write((msg.payload.len() as u64).into());
                        for payload in &msg.payload {
                            hasher.write(payload.0.into());
                        }
                    }
                    hasher.finish()
                },
                // Revert reason.
                match &receipt.execution_status {
                    ExecutionStatus::Succeeded => MontFelt::ZERO,
                    ExecutionStatus::Reverted { reason } => {
                        let mut keccak = sha3::Keccak256::default();
                        keccak.update(reason.as_bytes());
                        let mut hashed_bytes: [u8; 32] = keccak.finalize().into();
                        hashed_bytes[0] &= 0b00000011_u8; // Discard the six MSBs.
                        MontFelt::from_be_bytes(hashed_bytes)
                    }
                },
                // Execution resources:
                // L2 gas
                MontFelt::ZERO,
                // L1 gas consumed
                receipt.execution_resources.total_gas_consumed.l1_gas.into(),
                // L1 data gas consumed
                receipt
                    .execution_resources
                    .total_gas_consumed
                    .l1_data_gas
                    .into(),
            ])
            .into()
        })
        .collect();

    calculate_commitment_root::<PoseidonHash>(hashes).map(ReceiptCommitment)
}

fn calculate_commitment_root<H: FeltHash>(hashes: Vec<Felt>) -> Result<Felt> {
    let mut tree: TransactionOrEventTree<H> = Default::default();

    hashes
        .into_iter()
        .enumerate()
        .try_for_each(|(idx, final_hash)| {
            let idx: u64 = idx
                .try_into()
                .expect("too many transactions while calculating commitment");
            tree.set(idx, final_hash)
        })
        .context("Building transaction commitment tree")?;

    tree.commit()
}

#[derive(Debug, Deserialize)]
pub struct ClassHashParam {
    #[serde(rename = "classHash")]
    pub class_hash: ClassHash,
}

#[derive(Debug, Deserialize)]
pub struct BlockIdParam {
    #[serde(default, rename = "blockNumber")]
    pub block_number: Option<String>,
    #[serde(default, rename = "blockHash")]
    pub block_hash: Option<BlockHash>,
    #[serde(default, rename = "includeBlock")]
    pub include_block: Option<bool>,
    #[serde(default, rename = "headerOnly")]
    pub header_only: Option<bool>,
}

impl TryInto<BlockId> for BlockIdParam {
    type Error = ();

    fn try_into(self) -> Result<BlockId, Self::Error> {
        if let Some(n) = self.block_number {
            if n == "latest" {
                return Ok(BlockId::Latest);
            } else {
                let n: u64 = n.parse().map_err(|_| ())?;
                return Ok(BlockId::Number(BlockNumber::new_or_panic(n)));
            }
        }

        if let Some(h) = self.block_hash {
            return Ok(BlockId::Hash(h));
        }
        Err(())
    }
}

pub async fn get_signature_handler(
    Query(block_id): Query<BlockIdParam>,
    State(storage): State<Storage>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Convert query parameters into `BlockId`
    let block_id = match block_id.try_into() {
        Ok(block_id) => block_id,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Perform database operation to fetch the signature
    let signature_result = tokio::task::spawn_blocking(move || {
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        resolve_signature(&tx, block_id)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match signature_result {
        Ok(signature) => Ok(Json(json!(signature))),
        Err(e) => {
            tracing::error!("Error fetching signature: {:?}", e);
            let error = json!({
                "code": "StarknetErrorCode.BLOCK_NOT_FOUND",
                "message": "Block number not found"
            });
            Ok(Json(error))
        }
    }
}

pub async fn get_state_update_handler(
    Query(block_id): Query<BlockIdParam>,
    State(storage): State<Storage>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let include_block = block_id.include_block.unwrap_or(false);

    let block_id = match block_id.try_into() {
        Ok(block_id) => block_id,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let reorged = Arc::new(AtomicBool::new(false));

    let result = tokio::task::spawn_blocking(move || {
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let state_update = resolve_state_update(&tx, block_id, None, reorged.clone());
        let block = resolve_block(&tx, block_id);

        (state_update, block)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        (Ok(state_update), Ok(block)) => {
            if include_block {
                #[derive(Serialize)]
                struct StateUpdateWithBlock {
                    state_update: starknet_gateway_types::reply::StateUpdate,
                    block: starknet_gateway_types::reply::Block,
                }

                let reply = StateUpdateWithBlock {
                    state_update,
                    block,
                };

                Ok(Json(json!(reply)))
            } else {
                Ok(Json(json!(state_update)))
            }
        }
        _ => {
            let error = json!({
                "code": "StarknetErrorCode.BLOCK_NOT_FOUND",
                "message": "Block number not found"
            });
            Ok(Json(error))
        }
    }
}

pub async fn get_block_handler(
    Query(block_id): Query<BlockIdParam>,
    State(storage): State<Storage>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let header_only = block_id.header_only.unwrap_or(false);

    let block_id = match block_id.try_into() {
        Ok(block_id) => block_id,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let result = tokio::task::spawn_blocking(move || {
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        resolve_block(&tx, block_id)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Ok(block) => {
            if header_only {
                #[derive(Serialize)]
                struct HashAndNumber {
                    block_hash: BlockHash,
                    block_number: BlockNumber,
                }

                let reply = HashAndNumber {
                    block_hash: block.block_hash,
                    block_number: block.block_number,
                };

                Ok(Json(json!(reply)))
            } else {
                Ok(Json(json!(block)))
            }
        }
        Err(e) => {
            tracing::error!("Error fetching block: {:?}", e);
            let error = json!({
                "code": "StarknetErrorCode.BLOCK_NOT_FOUND",
                "message": "Block number not found"
            });
            Ok(Json(error))
        }
    }
}

pub async fn get_class_by_hash_handler(
    Query(class_hash_param): Query<ClassHashParam>,
    State(storage): State<Storage>,
) -> impl IntoResponse {
    let class_result = tokio::task::spawn_blocking(move || {
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        resolve_class(&tx, class_hash_param.class_hash)
    })
    .await;

    match class_result {
        Ok(Ok(class_data)) => {
            // Convert Vec<u8> to a compatible response body
            let body = Body::from(class_data);
            Response::builder()
                .header("content-type", "application/json")
                .body(body)
                .unwrap()
        }
        Ok(Err(_)) => {
            let error = format!(
                r#"{{"code": "StarknetErrorCode.UNDECLARED_CLASS", "message": "Class with hash "{}"not found" }}"#,
                class_hash_param.class_hash
            );
            let body = Body::from(error.to_string());
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(body)
                .unwrap()
        }
        Err(_) => {
            let body = Body::from("Internal server error");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "text/plain")
                .body(body)
                .unwrap()
        }
    }
}

pub async fn get_public_key_handler() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(json!(
        "0x1252b6bce1351844c677869c6327e80eae1535755b611c66b8f46e595b40eea"
    )))
}

pub async fn get_contract_addresses_handler(
    State(storage): State<Storage>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let chain = {
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        get_chain(&tx).unwrap()
    };
    let addresses = contract_addresses(chain).unwrap();

    Ok(Json(
        json!({"GpsStatementVerifier": addresses.gps, "Starknet": addresses.core}),
    ))
}
