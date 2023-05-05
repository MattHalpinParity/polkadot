// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Polkadot-specific RPCs implementation.

#![warn(missing_docs)]

use core::num;
use std::sync::Arc;

use jsonrpsee::RpcModule;
use polkadot_primitives::{AccountId, Balance, Block, BlockNumber, Hash, Nonce};
use sc_client_api::AuxStore;
use sc_consensus_babe::{BabeConfiguration, Epoch};
use sc_consensus_beefy::communication::notification::{
	BeefyBestBlockStream, BeefyVersionedFinalityProofStream,
};
use sc_consensus_grandpa::FinalityProofProvider;
use sc_rpc::chain;
pub use sc_rpc::{DenyUnsafe, SubscriptionTaskExecutor};
use sp_api::{ProvideRuntimeApi, HeaderT};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata, Backend};
use sp_consensus::SelectChain;
use sp_consensus_babe::BabeApi;
use sp_keystore::KeystorePtr;
use txpool_api::TransactionPool;

// Added for state_trieInfo RPC
use std::collections::{HashMap, HashSet, BTreeMap};
use serde::{Deserialize, Serialize};
use jsonrpsee::{
	core::{Error as JsonRpseeError, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorCode, ErrorObject},
};
use sp_runtime::traits::{
	Block as BlockT,
	Hash as HashT,
	HashFor,
};
use sp_state_machine::backend::AsTrieBackend;
use sp_trie::trie_types::{TrieDBBuilder};
use trie_db::node::NodeHandle;
use trie_db::{
	node::{decode_hash, NodePlan, Node, OwnedNode},
	TrieDBNodeIterator,
	TrieLayout,
	TrieHash,
	TrieError,
	triedb::TrieDB,
	NibbleVec,
	NibbleSlice,
};
use std::io::Write;

/// A type representing all RPC extensions.
pub type RpcExtension = RpcModule<()>;

/// Extra dependencies for BABE.
pub struct BabeDeps {
	/// BABE protocol config.
	pub babe_config: BabeConfiguration,
	/// BABE pending epoch changes.
	pub shared_epoch_changes: sc_consensus_epochs::SharedEpochChanges<Block, Epoch>,
	/// The keystore that manages the keys of the node.
	pub keystore: KeystorePtr,
}

/// Dependencies for GRANDPA
pub struct GrandpaDeps<B> {
	/// Voting round info.
	pub shared_voter_state: sc_consensus_grandpa::SharedVoterState,
	/// Authority set info.
	pub shared_authority_set: sc_consensus_grandpa::SharedAuthoritySet<Hash, BlockNumber>,
	/// Receives notifications about justification events from Grandpa.
	pub justification_stream: sc_consensus_grandpa::GrandpaJustificationStream<Block>,
	/// Executor to drive the subscription manager in the Grandpa RPC handler.
	pub subscription_executor: sc_rpc::SubscriptionTaskExecutor,
	/// Finality proof provider.
	pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Dependencies for BEEFY
pub struct BeefyDeps {
	/// Receives notifications about finality proof events from BEEFY.
	pub beefy_finality_proof_stream: BeefyVersionedFinalityProofStream<Block>,
	/// Receives notifications about best block events from BEEFY.
	pub beefy_best_block_stream: BeefyBestBlockStream<Block>,
	/// Executor to drive the subscription manager in the BEEFY RPC handler.
	pub subscription_executor: sc_rpc::SubscriptionTaskExecutor,
}

/// Full client dependencies
pub struct FullDeps<C, P, SC, B> {
	/// The client instance to use.
	pub client: Arc<C>,
	/// Transaction pool instance.
	pub pool: Arc<P>,
	/// The [`SelectChain`] Strategy
	pub select_chain: SC,
	/// A copy of the chain spec.
	pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
	/// Whether to deny unsafe calls
	pub deny_unsafe: DenyUnsafe,
	/// BABE specific dependencies.
	pub babe: BabeDeps,
	/// GRANDPA specific dependencies.
	pub grandpa: GrandpaDeps<B>,
	/// BEEFY specific dependencies.
	pub beefy: BeefyDeps,
}

/// TrieInfo result.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct TrieInfoResult {
	/// Block hash used to get trie info.
	pub block_hash: String,
	/// Block number.
	pub block_number: String,
	/// Number of trie nodes.
	pub num_nodes: u64,
	/// Number of inline nodes.
	pub num_inline_nodes: u64,
	/// Number of nodes of each type.
	pub node_type_count: [(String, u64); 5],
	/// Trie node child count histogram.
	pub child_count_histogram: [u64; 17],
	/// Trie node reference count histogram.
	pub reference_count_histogram: Vec<(u32, u64)>,
}

/// TrieInfo API
#[rpc(client, server)]
pub trait TrieInfoApi<BlockHash> {
	/// Test function
	#[method(name = "state_trieInfo", blocking)]
	fn trie_info(&self, at: Option<BlockHash>) -> RpcResult<TrieInfoResult>;
}

/// TrieInfo
pub struct TrieInfo<C, B, BA> {
	client: Arc<C>,
	backend: Arc<BA>,
	deny_unsafe: DenyUnsafe,
	_marker: std::marker::PhantomData<(B, BA)>,
}

impl<C, B, BA> TrieInfo<C, B, BA> {
	/// Create new
	pub fn new(client: Arc<C>, backend: Arc<BA>, deny_unsafe: DenyUnsafe) -> Self {
		TrieInfo { client, backend, deny_unsafe, _marker: Default::default() }
	}
}

fn write_histogram_file(filename: String, column0: String, column1: String, data: &Vec<(u32, u64)>) {
	let mut path = std::env::current_dir().expect("Cannot resolve current dir");
	path.push(filename);

	println!("Writing file: {}", path.display());

	let file = std::fs::OpenOptions::new()
		.create(true)
		.write(true)
		.truncate(true)
		.open(path.as_path()).expect("Failed to open file");

	let mut writer = std::io::BufWriter::new(file);

	let header_line = format!("{}, {}\n", column0, column1);
	writer.write_all(header_line.as_bytes()).expect("Unable to write data");

	for entry in data {
		let data_line = format!("{},{}\n", entry.0, entry.1);
		writer.write_all(data_line.as_bytes()).expect("Unable to write data");
	}
}

fn get_chain_hashes<B, BA>(backend: Arc<BA>, hash: <B as BlockT>::Hash) -> Vec<<B as BlockT>::Hash>
where
	B: BlockT,
	BA: 'static + sc_client_api::backend::Backend<B>,
{
	let mut blocks: Vec<<B as BlockT>::Hash> = Default::default();

	let mut last_hash = hash;
	blocks.push(last_hash);

	let mut last_valid = true;
	let mut num_allowed = 10000;
	while num_allowed > 0 && last_valid {
		num_allowed -= 1;
		last_valid = false;
		if let Ok(Some(header)) = backend.blockchain().header(last_hash) {
			let parent_hash = header.parent_hash().clone();
			if backend.state_at(parent_hash).is_ok() {
				last_hash = parent_hash;
				blocks.push(last_hash);
				last_valid = true;
			}
		}
	}

	blocks
}

fn append_optional_slice_and_nibble(
	src: &mut NibbleVec,
	o_slice: Option<&NibbleSlice>,
	o_index: Option<u8>,
) -> usize {
	let mut res = 0;
	if let Some(slice) = o_slice {
		src.append_partial(slice.right());
		res += slice.len();
	}
	if let Some(ix) = o_index {
		src.push(ix);
		res += 1;
	}
	res
}

fn clone_append_optional_slice_and_nibble(
	src: &NibbleVec,
	o_slice: Option<&NibbleSlice>,
	o_index: Option<u8>,
) -> NibbleVec {
	let mut p = src.clone();
	append_optional_slice_and_nibble(&mut p, o_slice, o_index);
	p
}

struct TrieProcessNode<'db, 'cache, 'a, L>
where
	L: TrieLayout,
{
	trie: &'db TrieDB<'db, 'cache, L>,
	node_key: NodeHandle<'a>,
	partial_key: NibbleVec,
	index: Option<u8>,
}

struct TrieProcessNodeData<L>
where
	L: TrieLayout,
{
	hash_done: HashSet<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out>,
	hash_references: HashMap<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out, u32>,

	num_nodes: u64,
	num_inline_nodes: u64,
	node_type_count: [(String, u64); 5],
	child_count_histogram: [u64; 17],
}

fn process_node<B, BA, L>(backend: Arc<BA>, node_to_process: TrieProcessNode<L>, process_node_data: &mut TrieProcessNodeData<L>) -> Result<(), JsonRpseeError>
where
	B: BlockT,
	BA: 'static + sc_client_api::backend::Backend<B>,
	L: TrieLayout,
{
	let node_handle = node_to_process.node_key;
	let partial_key = node_to_process.partial_key.as_prefix();
	let (node_hash, node_data) = match node_handle {
		NodeHandle::Hash(data) => {
			let node_hash = decode_hash::<L::Hash>(data)
				.ok_or_else(|| error_into_rpc_err("InvalidHash"))?;
			let node_data = node_to_process.trie.db().get(&node_hash, partial_key).ok_or_else(|| 
				error_into_rpc_err("InvalidStateRoot or IncompleteDatabase"))?;

			(Some(node_hash), node_data)
		},
		NodeHandle::Inline(data) => (None, data.to_vec()),
	};
	let owned_node = OwnedNode::new::<L::Codec>(node_data)
		.map_err(|e| error_into_rpc_err("DecoderError"))?;

	let mut continue_node = true;

	if let Some(hash) = node_hash {			
		if process_node_data.hash_done.contains(&hash) {
			continue_node = false;
		} else {
			process_node_data.hash_done.insert(hash);
		}
	}

	if !continue_node {
		return Ok(())
	}

	{
		process_node_data.num_nodes += 1;

		match node_hash {
			None => process_node_data.num_inline_nodes += 1,
			_ => {},
		};
	}

	match owned_node.node() {
		Node::Empty => {
			process_node_data.node_type_count[0].1 += 1;
		},
		Node::Leaf(slice, value) => {
			process_node_data.node_type_count[1].1 += 1;
		},
		Node::Extension(slice, item) => {
			process_node_data.node_type_count[2].1 += 1;
			process_node_data.child_count_histogram[1] += 1;
			let child_to_process = TrieProcessNode {
				trie: node_to_process.trie,
				node_key: item,
				partial_key: clone_append_optional_slice_and_nibble(
					&node_to_process.partial_key, Some(&slice), None
				),
				index: None,
			};
			process_node(backend.clone(), child_to_process, process_node_data)?;
		},
		Node::Branch(ref nodes, ref value) => {
			process_node_data.node_type_count[3].1 += 1;
		},
		Node::NibbledBranch(slice, nodes, value) => {
			process_node_data.node_type_count[4].1 += 1;
			let mut child_count = 0;
			for i in 0..nodes.len() {
				if let Some(child_handle) = nodes[i] {
					child_count += 1;
					
					match child_handle {
						NodeHandle::Hash(h) => {
							if let Some(child_node_hash) = decode_hash::<L::Hash>(h) {
								match process_node_data.hash_references.entry(child_node_hash) {
									std::collections::hash_map::Entry::Occupied(mut entry) => {
										*entry.get_mut() = entry.get() + 1;
									},
									std::collections::hash_map::Entry::Vacant(entry) => {
										entry.insert(1);
									},
								}
							}
						},
						NodeHandle::Inline(_) => {
						},
					}

					let child_to_process = TrieProcessNode {
						trie: node_to_process.trie,
						index: Some(i as u8),
						node_key: child_handle,
						partial_key: clone_append_optional_slice_and_nibble(
							&node_to_process.partial_key, Some(&slice), Some(i as u8),
						),
					};
					process_node(backend.clone(), child_to_process, process_node_data)?;
				}
			}
			process_node_data.child_count_histogram[child_count] += 1;
		},
	}

	Ok(())
}

impl<C, B, BA> TrieInfoApiServer<<B as BlockT>::Hash> for TrieInfo<C, B, BA>
where
	B: BlockT,
	C: Send + Sync + 'static + sc_client_api::HeaderBackend<B>,
	BA: 'static + sc_client_api::backend::Backend<B>,
{
	fn trie_info(&self, at: Option<<B as BlockT>::Hash>) -> RpcResult<TrieInfoResult> {
		self.deny_unsafe.check_if_safe()?;

		//self.backend.blockchain().leaves()

		let start_hash = at.unwrap_or_else(|| self.client.info().best_hash);
		//let start_hash = at.unwrap_or_else(|| self.client.info().finalized_hash);

		/* let mut chain_hashes: Vec<<B as BlockT>::Hash> = Default::default();
		chain_hashes.push(start_hash); */

		let chain_hashes = get_chain_hashes(self.backend.clone(), start_hash.clone());
		println!("Num blocks to process: {}", chain_hashes.len());
		/* for i in 0..chain_hashes.len() {
			if i < 50 || i > chain_hashes.len() - 50 {
				let block_hash = chain_hashes[i];
				let block_number = self.client.number(block_hash).map_err(error_into_rpc_err)?;
				let block_number = match block_number {
					Some(number) => {
						number.to_string()
					},
					None => {
						"Unknown".to_string()
					},
				};
				println!("Block: {}, ({})", block_number, chain_hashes[i].to_string());
			}
		} */

		let block_hash = start_hash.to_string();
		let block_number = self.client.number(start_hash).map_err(error_into_rpc_err)?;
		let block_number = match block_number {
			Some(number) => {
				number.to_string()
			},
			None => {
				"Unknown".to_string()
			},
		};

		// Sorted map of reference count to number of nodes with that reference count.
		let mut reference_count_tree: BTreeMap<u32, u64> = Default::default();
		/* {
			// Root node won't have its reference count included in the below code, so add it here.
			let count = reference_count_tree.get(&0).unwrap_or(&0u64) + 1;
			reference_count_tree.insert(0, count);
		} */

		let mut process_node_data = TrieProcessNodeData {
			hash_done: Default::default(),
			hash_references: Default::default(),
			num_nodes: 0u64,
			num_inline_nodes: 0u64,
			node_type_count: [
				("Empty".to_string(), 0u64),
				("Leaf".to_string(), 0u64),
				("Extension".to_string(), 0u64),
				("Branch".to_string(), 0u64),
				("NibbledBranch".to_string(), 0u64),
				],
			child_count_histogram: [0u64; 17],
		};

		for hash in chain_hashes {
			let state = self.backend.state_at(hash);

			if let Ok(state) = state {
				let trie_backend = state.as_trie_backend();
				let essence = trie_backend.essence();

				let trie = TrieDBBuilder::new(essence, essence.root()).build();

				let node_to_process = TrieProcessNode {
					trie: &trie,
					node_key: NodeHandle::Hash(essence.root().as_ref()),
					partial_key: NibbleVec::new(),
					index: None,
				};
				process_node(self.backend.clone(), node_to_process, &mut process_node_data)?;
			}
		}

		// Inline nodes only have 1 reference
		{
			let count = reference_count_tree.get(&1).unwrap_or(&0u64) + process_node_data.num_inline_nodes;
			reference_count_tree.insert(1, count);
		}

		for (_, reference_count) in process_node_data.hash_references.iter() {
			let count = reference_count_tree.get(reference_count).unwrap_or(&0u64) + 1;
			reference_count_tree.insert(*reference_count, count);
		}

		let data: Vec<(u32, u64)> = (0..process_node_data.child_count_histogram.len()).into_iter().map(|x| (x as u32, process_node_data.child_count_histogram[x])).collect();
		write_histogram_file("trie_child_count_histogram.txt".to_string(), "Child Count".to_string(), "Count".to_string(), &data);

		let data: Vec<(u32, u64)> = (0..=*reference_count_tree.last_key_value().unwrap_or((&0, &0)).0).into_iter().map(|x| (x as u32, reference_count_tree.get(&x).unwrap_or(&0u64).clone())).collect();
		write_histogram_file("trie_reference_count_histogram.txt".to_string(), "Reference Count".to_string(), "Count".to_string(), &data);

		let reference_count_histogram = Vec::from_iter(reference_count_tree.into_iter());

		write_histogram_file("trie_reference_count_histogram_sparse.txt".to_string(), "Reference Count".to_string(), "Count".to_string(), &reference_count_histogram);

		Ok(TrieInfoResult {
			block_hash: block_hash,
			block_number: block_number,
			num_nodes: process_node_data.num_nodes,
			num_inline_nodes: process_node_data.num_inline_nodes,
			node_type_count: process_node_data.node_type_count,
			child_count_histogram: process_node_data.child_count_histogram,
			reference_count_histogram,
		})
	}
}

fn error_into_rpc_err(err: impl std::fmt::Display) -> JsonRpseeError {
	JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
		ErrorCode::InternalError.code(),
		"Error while getting trie info",
		Some(err.to_string()),
	)))
}

/// Instantiate all RPC extensions.
pub fn create_full<C, P, SC, B>(
	deps: FullDeps<C, P, SC, B>,
	backend: Arc<B>,
) -> Result<RpcExtension, Box<dyn std::error::Error + Send + Sync>>
where
	C: ProvideRuntimeApi<Block>
		+ HeaderBackend<Block>
		+ AuxStore
		+ HeaderMetadata<Block, Error = BlockChainError>
		+ Send
		+ Sync
		+ 'static,
	C::Api: frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
	C::Api: mmr_rpc::MmrRuntimeApi<Block, <Block as sp_runtime::traits::Block>::Hash, BlockNumber>,
	C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
	C::Api: BabeApi<Block>,
	C::Api: BlockBuilder<Block>,
	P: TransactionPool + Sync + Send + 'static,
	SC: SelectChain<Block> + 'static,
	B: sc_client_api::Backend<Block> + Send + Sync + 'static,
	B::State: sc_client_api::StateBackend<sp_runtime::traits::HashFor<Block>>,
{
	use frame_rpc_system::{System, SystemApiServer};
	use mmr_rpc::{Mmr, MmrApiServer};
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
	use sc_consensus_babe_rpc::{Babe, BabeApiServer};
	use sc_consensus_beefy_rpc::{Beefy, BeefyApiServer};
	use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
	use sc_sync_state_rpc::{SyncState, SyncStateApiServer};
	use substrate_state_trie_migration_rpc::{StateMigration, StateMigrationApiServer};

	let mut io = RpcModule::new(());
	let FullDeps { client, pool, select_chain, chain_spec, deny_unsafe, babe, grandpa, beefy } =
		deps;
	let BabeDeps { keystore, babe_config, shared_epoch_changes } = babe;
	let GrandpaDeps {
		shared_voter_state,
		shared_authority_set,
		justification_stream,
		subscription_executor,
		finality_provider,
	} = grandpa;

	io.merge(StateMigration::new(client.clone(), backend.clone(), deny_unsafe).into_rpc())?;
	io.merge(System::new(client.clone(), pool.clone(), deny_unsafe).into_rpc())?;
	io.merge(TransactionPayment::new(client.clone()).into_rpc())?;
	io.merge(Mmr::new(client.clone()).into_rpc())?;
	io.merge(
		Babe::new(
			client.clone(),
			shared_epoch_changes.clone(),
			keystore,
			babe_config,
			select_chain,
			deny_unsafe,
		)
		.into_rpc(),
	)?;
	io.merge(
		Grandpa::new(
			subscription_executor,
			shared_authority_set.clone(),
			shared_voter_state,
			justification_stream,
			finality_provider,
		)
		.into_rpc(),
	)?;
	io.merge(
		SyncState::new(chain_spec, client.clone(), shared_authority_set, shared_epoch_changes)?.into_rpc(),
	)?;

	io.merge(
		Beefy::<Block>::new(
			beefy.beefy_finality_proof_stream,
			beefy.beefy_best_block_stream,
			beefy.subscription_executor,
		)?
		.into_rpc(),
	)?;

	io.merge(TrieInfo::new(client.clone(), backend.clone(), deny_unsafe).into_rpc())?;

	Ok(io)
}
