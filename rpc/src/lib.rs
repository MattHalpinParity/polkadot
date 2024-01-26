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

use std::sync::Arc;

use jsonrpsee::RpcModule;
use polkadot_primitives::{AccountId, Balance, Block, BlockNumber, Hash, Nonce};
use sc_client_api::AuxStore;
use sc_consensus_babe::{BabeConfiguration, Epoch};
use sc_consensus_beefy::communication::notification::{
	BeefyBestBlockStream, BeefyVersionedFinalityProofStream,
};
use sc_consensus_grandpa::FinalityProofProvider;
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
};
use sp_state_machine::backend::AsTrieBackend;
use sp_trie::trie_types::{TrieDBBuilder};
use trie_db::node::NodeHandle;
use trie_db::{
	node::{decode_hash, Node, OwnedNode, Value},
	TrieLayout,
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
	/// Number of blocks processed
	pub num_blocks_processed: u64,
	/// Number of trie nodes.
	pub num_nodes: u64,
	/// Number of inline nodes.
	pub num_inline_nodes: u64,
	/// Number of inline leaf nodes.
	pub num_inline_leaf_nodes: u64,
	/// Number of inline branch nodes.
	pub num_inline_branch_nodes: u64,
	/// Number of nodes unique to the head block.
	pub average_num_new_nodes: f64,
	/// Number of values.
	pub num_values: u64,
	/// Number of leaf values.
	pub num_leaf_values: u64,
	/// Number of branch values.
	pub num_branch_values: u64,
	/// Number of inline values.
	pub num_inline_values: u64,
	/// Number of node values.
	pub num_node_values: u64,
	/// Number of nodes of each type.
	pub node_type_count: [(String, u64); 5],
	/// Trie node child count histogram.
	pub child_count_histogram: [u64; 17],
	/// Trie node reference count histogram.
	pub reference_count_histogram: Vec<(u32, u64)>,
	/// Trie node depth histogram.
	pub depth_histogram: Vec<(u32, u64)>,
	/// Child count histogram for each depth
	pub depth_child_count_histograms: Vec<(u32, [u64; 17])>,
	/// Key length histogram
	pub key_length_histogram: Vec<(u32, u64)>,
	/// Value length histogram
	pub value_length_histogram: Vec<(u32, u64)>,
}

/// TrieInfo blocks enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieInfoBlocks {
	/// Best block only
	Best,
	/// Head of finalized chain only
	Finalized,
	/// Best block and parent chain
	BestAndChain,
	/// Finalized chain
	FinalizedAndChain,
	/// All leaves and their parent chains
	LeavesAndChains,
}

/// TrieInfo API
#[rpc(client, server)]
pub trait TrieInfoApi<BlockHash> {
	/// Test function
	#[method(name = "state_trieInfo", blocking)]
	fn trie_info(&self, blocks: Option<TrieInfoBlocks>, at: Option<BlockHash>) -> RpcResult<TrieInfoResult>;
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

fn write_histogram_file<A, B>(filename: String, column0: String, column1: String, data: &Vec<(A, B)>) 
where
	A: std::fmt::Display,
	B: std::fmt::Display,
{
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

fn write_histogram_file_3_columns<A, B, C>(filename: String, column0: String, column1: String, column2: String, data: &Vec<(A, B, C)>) 
where
	A: std::fmt::Display,
	B: std::fmt::Display,
	C: std::fmt::Display,
{
	let mut path = std::env::current_dir().expect("Cannot resolve current dir");
	path.push(filename);

	println!("Writing file: {}", path.display());

	let file = std::fs::OpenOptions::new()
		.create(true)
		.write(true)
		.truncate(true)
		.open(path.as_path()).expect("Failed to open file");

	let mut writer = std::io::BufWriter::new(file);

	let header_line = format!("{}, {}, {}\n", column0, column1, column2);
	writer.write_all(header_line.as_bytes()).expect("Unable to write data");

	for entry in data {
		let data_line = format!("{},{},{}\n", entry.0, entry.1, entry.2);
		writer.write_all(data_line.as_bytes()).expect("Unable to write data");
	}
}

fn generate_code_parameter_text<I>(prefix: String, suffix: String, values: I) -> String
where
	I: IntoIterator<Item = String>,
{
	let mut text: String = prefix;

	/* let mut line = "".to_string();
	let mut added_value = false;
	for s in values {
		let add_text = s + ",";

		let mut add_len = add_text.len();
		if added_value {
			add_len += 1;
		}

		// 4 is for the tab that will be added at the start of the line.
		let can_add = line.len() + add_len + 4 < 100;
		if can_add {
			if added_value {
				line += " ";
			}
			line += &add_text;
			added_value = true;
		} else {
			text += "\t";
			text += &line;
			text += "\n";
			line = add_text;
			added_value = true;
		}
	}
	if line.len() > 0 {
		text += "\t";
		text += &line;
		text += "\n";
	} */
	for s in values {
		let add_text = s + ",";
		text += "\t";
		text += &add_text;
		text += "\n";
	}

	text += &suffix;
	text
}

fn add_chain_hashes<B, BA>(backend: Arc<BA>, hash: <B as BlockT>::Hash, chain_hashes: &mut Vec<<B as BlockT>::Hash>, hash_done: &mut HashSet<<B as BlockT>::Hash>)
where
	B: BlockT,
	BA: 'static + sc_client_api::backend::Backend<B>,
{
	let mut last_hash = hash;

	if !hash_done.contains(&last_hash) {
		hash_done.insert(last_hash);
		chain_hashes.push(last_hash);
	}

	let mut last_valid = true;
	let mut num_allowed = 10000;
	while num_allowed > 0 && last_valid {
		num_allowed -= 1;
		last_valid = false;
		if let Ok(Some(header)) = backend.blockchain().header(last_hash) {
			let parent_hash = header.parent_hash().clone();
			if backend.state_at(parent_hash).is_ok() {
				last_hash = parent_hash;

				if !hash_done.contains(&last_hash) {
					hash_done.insert(last_hash);
					chain_hashes.push(last_hash);
					last_valid = true;
				}
			}
		}
	}
}

fn add_chain_hash_age<B, BA>(backend: Arc<BA>, hash: <B as BlockT>::Hash, chain_hash_age: &mut Vec<(<B as BlockT>::Hash, u64)>, hash_done: &mut HashSet<<B as BlockT>::Hash>)
where
	B: BlockT,
	BA: 'static + sc_client_api::backend::Backend<B>,
{
	let mut last_hash = hash;
	let mut last_age = 0;

	if !hash_done.contains(&last_hash) {
		hash_done.insert(last_hash);
		chain_hash_age.push((last_hash, last_age));
	}

	let mut last_valid = true;
	let mut num_allowed = 10000;
	while num_allowed > 0 && last_valid {
		num_allowed -= 1;
		last_valid = false;
		if let Ok(Some(header)) = backend.blockchain().header(last_hash) {
			let parent_hash = header.parent_hash().clone();
			if backend.state_at(parent_hash).is_ok() {
				last_hash = parent_hash;
				last_age += 1;

				if !hash_done.contains(&last_hash) {
					hash_done.insert(last_hash);
					chain_hash_age.push((last_hash, last_age));
					last_valid = true;
				}
			}
		}
	}
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

	parent_hash: Option<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out>,
	index: Option<u8>,
}

struct TrieProcessNodeData<L>
where
	L: TrieLayout,
{
	hash_done: HashSet<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out>,
	hash_references: HashMap<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out, u32>,
	hash_depth: HashMap<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out, u32>,
	hash_child_count: HashMap<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out, u8>,
	hash_age: HashMap<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out, u64>,

	//hash_depths: HashMap<<<L as TrieLayout>::Hash as trie_db::Hasher>::Out, HashSet<u32>>,

	depth_age_histogram: BTreeMap<u32, BTreeMap<u64, u64>>,

	num_nodes: u64,
	num_inline_nodes: u64,
	num_inline_leaf_nodes: u64,
	num_inline_branch_nodes: u64,
	average_num_new_nodes: f64,
	node_type_count: [(String, u64); 5],
	child_count_histogram: [u64; 17],
	key_length_histogram: BTreeMap<u32, u64>,
	num_values: u64,
	num_leaf_values: u64,
	num_branch_values: u64,
	num_inline_values: u64,
	num_node_values: u64,
	value_length_histogram: BTreeMap<u32, u64>,
}

impl<L> TrieProcessNodeData<L> 
where
	L: TrieLayout,
{
	fn add_depth_age(&mut self, depth: u32, age: u64) {

		if self.depth_age_histogram.contains_key(&depth) {
			let histogram = self.depth_age_histogram.get_mut(&depth).unwrap();
			let count = histogram.get(&age).unwrap_or(&0u64) + 1;
			histogram.insert(age, count);
		} else {
			let mut histogram: BTreeMap<u64, u64> = Default::default();
			let count = 1;
			histogram.insert(age, count);
			self.depth_age_histogram.insert(depth, histogram);
		}
	}
}

fn adjust_node_age<B, BA, L>(backend: Arc<BA>, node_to_process: TrieProcessNode<L>, age: u64, process_node_data: &mut TrieProcessNodeData<L>) -> Result<(), JsonRpseeError>
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
		.map_err(|_e| error_into_rpc_err("DecoderError"))?;

	// If the node doesn't have a hash (because it is inline) then see if we can create a hash from parent hash and index in parent.
	let mut node_hash = node_hash;
	if node_hash.is_none() {
		if let Some(parent_hash) = node_to_process.parent_hash {
			if let Some(index) = node_to_process.index {
				node_hash = Some(<<L as TrieLayout>::Hash as trie_db::Hasher>::hash([parent_hash.as_ref(), &[index]].concat().as_slice()));
			}
		}
	}

	let mut continue_node = true;

	if let Some(hash) = node_hash {		
		/* if process_node_data.hash_done.contains(&hash) */ {
			match process_node_data.hash_age.entry(hash) {
				std::collections::hash_map::Entry::Occupied(mut entry) => {
					if age > *entry.get() {
						*entry.get_mut() = age;
					}
					else {
						continue_node = false;
					}
				},
				std::collections::hash_map::Entry::Vacant(entry) => {
					entry.insert(age);
				},
			}
		}
	}

	if !continue_node {
		return Ok(())
	}

	match owned_node.node() {
		Node::Empty => {
		},
		Node::Leaf(..) => {
		},
		Node::Extension(slice, item) => {
			let child_to_process = TrieProcessNode {
				trie: node_to_process.trie,
				node_key: item,
				partial_key: clone_append_optional_slice_and_nibble(
					&node_to_process.partial_key, Some(&slice), None
				),
				parent_hash: node_hash,
				index: Some(0),
			};
			adjust_node_age(backend.clone(), child_to_process, age, process_node_data)?;
		},
		Node::Branch(..) => {
		},
		Node::NibbledBranch(slice, nodes, _value) => {
			for i in 0..nodes.len() {
				if let Some(child_handle) = nodes[i] {
					let child_to_process = TrieProcessNode {
						trie: node_to_process.trie,
						node_key: child_handle,
						partial_key: clone_append_optional_slice_and_nibble(
							&node_to_process.partial_key, Some(&slice), Some(i as u8),
						),
						parent_hash: node_hash,
						index: Some(i as u8),
					};
					adjust_node_age(backend.clone(), child_to_process, age, process_node_data)?;
				}
			}
		},
	}

	Ok(())
}

fn add_depth_age<B, BA, L>(backend: Arc<BA>, node_to_process: TrieProcessNode<L>, depth: u32, parent_age: u64, process_node_data: &mut TrieProcessNodeData<L>) -> Result<(), JsonRpseeError>
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
		.map_err(|_e| error_into_rpc_err("DecoderError"))?;

	// If the node doesn't have a hash (because it is inline) then see if we can create a hash from parent hash and index in parent.
	let mut node_hash = node_hash;
	if node_hash.is_none() {
		if let Some(parent_hash) = node_to_process.parent_hash {
			if let Some(index) = node_to_process.index {
				node_hash = Some(<<L as TrieLayout>::Hash as trie_db::Hasher>::hash([parent_hash.as_ref(), &[index]].concat().as_slice()));
			}
		}
	}

	let mut continue_node = true;

	if let Some(hash) = node_hash {		
		if depth > 0 {
			if let Some(age) = process_node_data.hash_age.get(&hash) {
				let age = age.clone();

				if age == parent_age {
					process_node_data.average_num_new_nodes += 1.0f64;
				}

				process_node_data.add_depth_age(depth - 1, age - parent_age);
	
				if age > parent_age {
					continue_node = false;
				}
			}	
		}
	}

	if !continue_node {
		return Ok(())
	}

	match owned_node.node() {
		Node::Empty => {
		},
		Node::Leaf(..) => {
		},
		Node::Extension(slice, item) => {
			let child_to_process = TrieProcessNode {
				trie: node_to_process.trie,
				node_key: item,
				partial_key: clone_append_optional_slice_and_nibble(
					&node_to_process.partial_key, Some(&slice), None
				),
				parent_hash: node_hash,
				index: Some(0),
			};
			add_depth_age(backend.clone(), child_to_process, depth + 1, parent_age, process_node_data)?;
		},
		Node::Branch(..) => {
		},
		Node::NibbledBranch(slice, nodes, _value) => {
			for i in 0..nodes.len() {
				if let Some(child_handle) = nodes[i] {
					let child_to_process = TrieProcessNode {
						trie: node_to_process.trie,
						node_key: child_handle,
						partial_key: clone_append_optional_slice_and_nibble(
							&node_to_process.partial_key, Some(&slice), Some(i as u8),
						),
						parent_hash: node_hash,
						index: Some(i as u8),
					};
					add_depth_age(backend.clone(), child_to_process, depth + 1, parent_age, process_node_data)?;
				}
			}
		},
	}

	Ok(())
}

fn adjust_node_depth<B, BA, L>(backend: Arc<BA>, node_to_process: TrieProcessNode<L>, depth: u32, process_node_data: &mut TrieProcessNodeData<L>) -> Result<(), JsonRpseeError>
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
		.map_err(|_e| error_into_rpc_err("DecoderError"))?;

	// If the node doesn't have a hash (because it is inline) then see if we can create a hash from parent hash and index in parent.
	let mut node_hash = node_hash;
	if node_hash.is_none() {
		if let Some(parent_hash) = node_to_process.parent_hash {
			if let Some(index) = node_to_process.index {
				node_hash = Some(<<L as TrieLayout>::Hash as trie_db::Hasher>::hash([parent_hash.as_ref(), &[index]].concat().as_slice()));
			}
		}
	}

	let mut continue_node = true;

	if let Some(hash) = node_hash {			
		match process_node_data.hash_depth.entry(hash) {
			std::collections::hash_map::Entry::Occupied(mut entry) => {
				if depth < *entry.get() {
					*entry.get_mut() = depth;
				}
				else {
					continue_node = false;
				}
			},
			std::collections::hash_map::Entry::Vacant(entry) => {
				entry.insert(depth);
			},
		}
	}

	if !continue_node {
		return Ok(())
	}

	match owned_node.node() {
		Node::Empty => {
		},
		Node::Leaf(..) => {
		},
		Node::Extension(slice, item) => {
			let child_to_process = TrieProcessNode {
				trie: node_to_process.trie,
				node_key: item,
				partial_key: clone_append_optional_slice_and_nibble(
					&node_to_process.partial_key, Some(&slice), None
				),
				parent_hash: node_hash,
				index: Some(0),
			};
			adjust_node_depth(backend.clone(), child_to_process, depth + 1, process_node_data)?;
		},
		Node::Branch(..) => {
		},
		Node::NibbledBranch(slice, nodes, _value) => {
			for i in 0..nodes.len() {
				if let Some(child_handle) = nodes[i] {
					let child_to_process = TrieProcessNode {
						trie: node_to_process.trie,
						node_key: child_handle,
						partial_key: clone_append_optional_slice_and_nibble(
							&node_to_process.partial_key, Some(&slice), Some(i as u8),
						),
						parent_hash: node_hash,
						index: Some(i as u8),
					};
					adjust_node_depth(backend.clone(), child_to_process, depth + 1, process_node_data)?;
				}
			}
		},
	}

	Ok(())
}

fn process_node<B, BA, L>(backend: Arc<BA>, node_to_process: TrieProcessNode<L>, depth: u32, process_node_data: &mut TrieProcessNodeData<L>) -> Result<(), JsonRpseeError>
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
		.map_err(|_e| error_into_rpc_err("DecoderError"))?;

	let is_inline = node_hash.is_none();

	// If the node doesn't have a hash (because it is inline) then see if we can create a hash from parent hash and index in parent.
	let mut node_hash = node_hash;
	if node_hash.is_none() {
		if let Some(parent_hash) = node_to_process.parent_hash {
			if let Some(index) = node_to_process.index {
				node_hash = Some(<<L as TrieLayout>::Hash as trie_db::Hasher>::hash([parent_hash.as_ref(), &[index]].concat().as_slice()));
			}
		}
	}

	let mut continue_node = true;

	if let Some(hash) = node_hash {
		if process_node_data.hash_done.contains(&hash) {
			continue_node = false;
		} else {
			process_node_data.hash_done.insert(hash);
		}

		match process_node_data.hash_depth.entry(hash) {
			std::collections::hash_map::Entry::Occupied(entry) => {
				if depth < *entry.get() {
					// Adjust node and child depths.
					let node_to_process_copy = TrieProcessNode {
						trie: node_to_process.trie,
						node_key: node_to_process.node_key,
						partial_key: node_to_process.partial_key.clone(),
						parent_hash: node_to_process.parent_hash,
						index: node_to_process.index,
					};
					adjust_node_depth(backend.clone(), node_to_process_copy, depth, process_node_data)?;
				}
			},
			std::collections::hash_map::Entry::Vacant(entry) => {
				entry.insert(depth);
			},
		}

		/* match process_node_data.hash_depths.entry(hash) {
			std::collections::hash_map::Entry::Occupied(mut entry) => {
				entry.get_mut().insert(depth);
			},
			std::collections::hash_map::Entry::Vacant(entry) => {
				let mut depths: HashSet<u32> = Default::default();
				depths.insert(depth);
				entry.insert(depths);
			},
		} */
	}

	if !continue_node {
		return Ok(())
	}

	process_node_data.num_nodes += 1;

	if is_inline {
		process_node_data.num_inline_nodes += 1;
	}

	let mut child_count = 0;
	match owned_node.node() {
		Node::Empty => {
			process_node_data.node_type_count[0].1 += 1;
		},
		Node::Leaf(slice, value) => {
			process_node_data.node_type_count[1].1 += 1;

			if is_inline {
				process_node_data.num_inline_leaf_nodes += 1;
			}

			process_node_data.num_values += 1;
			process_node_data.num_leaf_values += 1;

			let value_key = clone_append_optional_slice_and_nibble(&node_to_process.partial_key, Some(&slice), None);
			let key_nibble_length = value_key.len() as u32;
			let key_length = key_nibble_length / 2;

			let count = process_node_data.key_length_histogram.get(&key_length).unwrap_or(&0u64) + 1;
			process_node_data.key_length_histogram.insert(key_length, count);

			match value {
				Value::Inline(value) => {
					process_node_data.num_inline_values += 1;

					let value_length = value.len() as u32;

					let count = process_node_data.value_length_histogram.get(&value_length).unwrap_or(&0u64) + 1;
					process_node_data.value_length_histogram.insert(value_length, count);
				},
				Value::Node(hash) => {
					process_node_data.num_node_values += 1;

					let mut res = <<L as TrieLayout>::Hash as trie_db::Hasher>::Out::default();
					res.as_mut().copy_from_slice(hash);

					let prefix = value_key.as_prefix();
					let value = node_to_process.trie.db().get(&res, prefix).ok_or_else(|| 
						error_into_rpc_err("No leaf value found"))?;

					let value_length = value.len() as u32;

					let count = process_node_data.value_length_histogram.get(&value_length).unwrap_or(&0u64) + 1;
					process_node_data.value_length_histogram.insert(value_length, count);
				}
			}
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
				parent_hash: node_hash,
				index: Some(0),
			};
			process_node(backend.clone(), child_to_process, depth + 1, process_node_data)?;
			child_count = 1;
		},
		Node::Branch(ref _nodes, ref _value) => {
			process_node_data.node_type_count[3].1 += 1;
		},
		Node::NibbledBranch(slice, nodes, value) => {
			process_node_data.node_type_count[4].1 += 1;

			if is_inline {
				process_node_data.num_inline_branch_nodes += 1;
			}

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
						node_key: child_handle,
						partial_key: clone_append_optional_slice_and_nibble(
							&node_to_process.partial_key, Some(&slice), Some(i as u8),
						),
						parent_hash: node_hash,
						index: Some(i as u8),
					};
					process_node(backend.clone(), child_to_process, depth + 1, process_node_data)?;
				}
			}
			process_node_data.child_count_histogram[child_count] += 1;

			if let Some(value) = value {
				process_node_data.num_values += 1;
				process_node_data.num_branch_values += 1;

				let value_key = clone_append_optional_slice_and_nibble(&node_to_process.partial_key, Some(&slice), None);
				let key_nibble_length = value_key.len() as u32;
				let key_length = key_nibble_length / 2;

				let count = process_node_data.key_length_histogram.get(&key_length).unwrap_or(&0u64) + 1;
				process_node_data.key_length_histogram.insert(key_length, count);

				match value {
				Value::Inline(value) => {
					process_node_data.num_inline_values += 1;

					let value_length = value.len() as u32;

					let count = process_node_data.value_length_histogram.get(&value_length).unwrap_or(&0u64) + 1;
					process_node_data.value_length_histogram.insert(value_length, count);
				},
				Value::Node(hash) => {
					process_node_data.num_node_values += 1;

					let mut res = <<L as TrieLayout>::Hash as trie_db::Hasher>::Out::default();
					res.as_mut().copy_from_slice(hash);

					let prefix = value_key.as_prefix();
					let value = node_to_process.trie.db().get(&res, prefix).ok_or_else(|| 
						error_into_rpc_err("No leaf value found"))?;

					let value_length = value.len() as u32;

					let count = process_node_data.value_length_histogram.get(&value_length).unwrap_or(&0u64) + 1;
					process_node_data.value_length_histogram.insert(value_length, count);
				}
			}
			}
		},
	}

	if let Some(hash) = node_hash {
		process_node_data.hash_child_count.insert(hash, child_count as u8);
	}

	Ok(())
}

impl<C, B, BA> TrieInfoApiServer<<B as BlockT>::Hash> for TrieInfo<C, B, BA>
where
	B: BlockT,
	C: Send + Sync + 'static + sc_client_api::HeaderBackend<B>,
	BA: 'static + sc_client_api::backend::Backend<B>,
{
	fn trie_info(&self, blocks: Option<TrieInfoBlocks>, at: Option<<B as BlockT>::Hash>) -> RpcResult<TrieInfoResult> {
		self.deny_unsafe.check_if_safe()?;

		let blocks = match blocks {
			Some(source) => source,
			None => TrieInfoBlocks::Best,
		};

		let mut chain_hashes: Vec<<B as BlockT>::Hash> = Default::default();

		let start_hash = match blocks {
			TrieInfoBlocks::Best => {
				let hash = at.unwrap_or_else(|| self.client.info().best_hash);
				chain_hashes.push(hash);
				hash
			},
			TrieInfoBlocks::Finalized => {
				let hash = at.unwrap_or_else(|| self.client.info().finalized_hash);
				chain_hashes.push(hash);
				hash
			},
			TrieInfoBlocks::BestAndChain => {
				let hash = at.unwrap_or_else(|| self.client.info().best_hash);
				let mut hash_done: HashSet<<B as BlockT>::Hash> = Default::default();
				add_chain_hashes(self.backend.clone(), hash.clone(), &mut chain_hashes, &mut hash_done);
				hash
			},
			TrieInfoBlocks::FinalizedAndChain => {
				let hash = at.unwrap_or_else(|| self.client.info().finalized_hash);
				let mut hash_done: HashSet<<B as BlockT>::Hash> = Default::default();
				add_chain_hashes(self.backend.clone(), hash.clone(), &mut chain_hashes, &mut hash_done);
				hash
			},
			TrieInfoBlocks::LeavesAndChains => {
				let mut hash_done: HashSet<<B as BlockT>::Hash> = Default::default();
				let leaves = self.backend.blockchain().leaves();
				if let Ok(leaves) = leaves {
					for leaf in leaves {
						add_chain_hashes(self.backend.clone(), leaf.clone(), &mut chain_hashes, &mut hash_done);
					}
				}
				let hash = at.unwrap_or_else(|| self.client.info().best_hash);
				hash
			},
		};

		let num_blocks_processed = chain_hashes.len() as u64;

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

		let mut process_node_data = TrieProcessNodeData {
			hash_done: Default::default(),
			hash_references: Default::default(),
			hash_depth: Default::default(),
			hash_child_count: Default::default(),
			hash_age: Default::default(),
			//hash_depths: Default::default(),
			depth_age_histogram: Default::default(),
			num_nodes: 0u64,
			num_inline_nodes: 0u64,
			num_inline_leaf_nodes: 0u64,
			num_inline_branch_nodes: 0u64,
			average_num_new_nodes: 0.0f64,
			node_type_count: [
				("Empty".to_string(), 0u64),
				("Leaf".to_string(), 0u64),
				("Extension".to_string(), 0u64),
				("Branch".to_string(), 0u64),
				("NibbledBranch".to_string(), 0u64),
				],
			child_count_histogram: [0u64; 17],
			key_length_histogram: Default::default(),
			num_values: 0u64,
			num_leaf_values: 0u64,
			num_branch_values: 0u64,
			num_inline_values: 0u64,
			num_node_values: 0u64,		
			value_length_histogram: Default::default(),
		};

		for hash in chain_hashes.iter() {
			let state = self.backend.state_at(hash.clone());

			if let Ok(state) = state {
				let trie_backend = state.as_trie_backend();
				let essence = trie_backend.essence();

				let trie = TrieDBBuilder::new(essence, essence.root()).build();

				let node_to_process = TrieProcessNode {
					trie: &trie,
					node_key: NodeHandle::Hash(essence.root().as_ref()),
					partial_key: NibbleVec::new(),
					parent_hash: None,
					index: None,
				};
				process_node(self.backend.clone(), node_to_process, 0, &mut process_node_data)?;
			}
		}

		if chain_hashes.len() == 1 {
			// If we have only processed one block then we can determine node ages by looking at the chain
			let mut chain_hash_age: Vec<(<B as BlockT>::Hash, u64)> = Default::default();
			let mut hash_done: HashSet<<B as BlockT>::Hash> = Default::default();
			add_chain_hash_age(self.backend.clone(), chain_hashes[0], &mut chain_hash_age, &mut hash_done);

			for (hash, age) in chain_hash_age.iter().rev() {
				let state = self.backend.state_at(hash.clone());
	
				if let Ok(state) = state {
					let trie_backend = state.as_trie_backend();
					let essence = trie_backend.essence();
	
					let trie = TrieDBBuilder::new(essence, essence.root()).build();
	
					let node_to_process = TrieProcessNode {
						trie: &trie,
						node_key: NodeHandle::Hash(essence.root().as_ref()),
						partial_key: NibbleVec::new(),
						parent_hash: None,
						index: None,
					};
					adjust_node_age(self.backend.clone(), node_to_process, *age, &mut process_node_data)?;
				}
			}

			let mut num_source_trees = 0;
			for i in 0..chain_hash_age.len() {
				if i < 64 {
					let (hash, age) = chain_hash_age[i];

					let state = self.backend.state_at(hash.clone());
		
					if let Ok(state) = state {
						let trie_backend = state.as_trie_backend();
						let essence = trie_backend.essence();
		
						let trie = TrieDBBuilder::new(essence, essence.root()).build();
		
						let node_to_process = TrieProcessNode {
							trie: &trie,
							node_key: NodeHandle::Hash(essence.root().as_ref()),
							partial_key: NibbleVec::new(),
							parent_hash: None,
							index: None,
						};
						add_depth_age(self.backend.clone(), node_to_process, 0, age, &mut process_node_data)?;

						num_source_trees += 1;
					}
				}
			}

			process_node_data.average_num_new_nodes *= 1.0f64 / num_source_trees as f64;
		}

		let mut depth_count_tree: BTreeMap<u32, u64> = Default::default();
		for (_, depth) in process_node_data.hash_depth.iter() {
			let count = depth_count_tree.get(&depth).unwrap_or(&0u64) + 1;
			depth_count_tree.insert(*depth, count);
		}
		let depth_histogram = Vec::from_iter(depth_count_tree.into_iter());

		let mut depth_child_count_tree: BTreeMap<u32, [u64; 17]> = Default::default();
		for (hash, depth) in process_node_data.hash_depth.iter() {
			if let Some(child_count) = process_node_data.hash_child_count.get(hash) {
				if depth_child_count_tree.contains_key(depth) {
					let histogram = depth_child_count_tree.get_mut(depth).unwrap();
					histogram[*child_count as usize] += 1;
				} else {
					let mut histogram = [0u64; 17];
					histogram[*child_count as usize] += 1;
					depth_child_count_tree.insert(*depth, histogram);
				}
			}
		}
		let depth_child_count_histograms: Vec<(u32, [u64; 17])> = Vec::from_iter(depth_child_count_tree.into_iter());

		/* let mut depth_age_tree: BTreeMap<u32, BTreeMap<u64, u64>> = Default::default();
		for (hash, age) in process_node_data.hash_age.iter() {
			if let Some(depth) = process_node_data.hash_depth.get(hash) {
				if depth_age_tree.contains_key(depth) {
					let histogram = depth_age_tree.get_mut(depth).unwrap();
					let count = histogram.get(age).unwrap_or(&0u64) + 1;
					histogram.insert(*age, count);
				} else {
					let mut histogram: BTreeMap<u64, u64> = Default::default();
					let count = histogram.get(age).unwrap_or(&0u64) + 1;
					histogram.insert(*age, count);
					depth_age_tree.insert(*depth, histogram);
				}
			}
		}
		let depth_age_histograms: Vec<(u32, Vec<(u64, u64)>)> = Vec::from_iter(depth_age_tree.into_iter().map(|(depth, age_histogram)| {
			(depth, Vec::from_iter(age_histogram.into_iter()))
		})); */
		let depth_age_histograms: Vec<(u32, Vec<(u64, u64)>)> = Vec::from_iter(process_node_data.depth_age_histogram.into_iter().map(|(depth, age_histogram)| {
			(depth, Vec::from_iter(age_histogram.into_iter()))
		}));

		let key_length_histogram = Vec::from_iter(process_node_data.key_length_histogram.into_iter());

		let value_length_histogram = Vec::from_iter(process_node_data.value_length_histogram.into_iter());

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

		write_histogram_file("trie_depth_histogram.txt".to_string(), "Depth".to_string(), "Count".to_string(), &depth_histogram);

		let mut depth_child_count_histograms_expanded: Vec<(u32, u32, u64)> = Default::default();
		for (depth, histogram) in &depth_child_count_histograms {
			let mut data: Vec<(u32, u32, u64)> = (0..histogram.len()).into_iter().map(|x| (*depth, x as u32, histogram[x])).collect();
			depth_child_count_histograms_expanded.append(&mut data);
		}
		write_histogram_file_3_columns("trie_depth_child_count_histograms.txt".to_string(), "Depth".to_string(), "Child Count".to_string(), "Count".to_string(), &depth_child_count_histograms_expanded);

		write_histogram_file("trie_key_length_histogram.txt".to_string(), "Key Length".to_string(), "Count".to_string(), &key_length_histogram);

		write_histogram_file("trie_value_length_histogram.txt".to_string(), "Value Length".to_string(), "Count".to_string(), &value_length_histogram);

		// Write parameter code to file
		{
			let mut code_text: String = "".to_string();

			code_text += &format!("pub const NUM_NODES: u32 = {};\n", process_node_data.num_nodes);
			code_text += &format!("pub const AVERAGE_NUM_NEW_NODES: f64 = {};\n", process_node_data.average_num_new_nodes);

			code_text += "\n";

			let depth_child_count_histograms_values = depth_child_count_histograms.iter().map(|x| {
				let mut histogram_text: String = "".to_string();
				for i in 0..x.1.len() {
					if i > 0 {
						histogram_text += &", ";
					}
					histogram_text += &format!("{}", x.1[i]);
				}
				format!("({}, [{}])", x.0, histogram_text).to_string()
			});
			code_text += &generate_code_parameter_text("pub const DEPTH_CHILD_COUNT_HISTOGRAMS: &[(u32, [u32; 17])] = &[\n".to_string(), "];\n".to_string(), depth_child_count_histograms_values);

			code_text += "\n";

			let depth_age_histograms_values = depth_age_histograms.iter().map(|(depth, age_histogram)| {
				let mut histogram_text: String = "".to_string();
				for i in 0..age_histogram.len() {
					if i > 0 {
						histogram_text += &", ";
					}
					histogram_text += &format!("({}, {})", age_histogram[i].0, age_histogram[i].1);
				}
				format!("({}, &[{}])", depth, histogram_text).to_string()
			});
			code_text += &generate_code_parameter_text("pub const DEPTH_AGE_HISTOGRAMS: &[(u32, &[(u32, u32)])] = &[\n".to_string(), "];\n".to_string(), depth_age_histograms_values);

			code_text += "\n";

			/* let key_length_text_values = key_length_histogram.iter().map(|x| format!("({}, {})", x.0, x.1).to_string());
			code_text += &generate_code_parameter_text("pub const KEY_LENGTH_HISTOGRAM: &[(u32, u32)] = &[\n".to_string(), "];\n".to_string(), key_length_text_values);

			code_text += "\n"; */

			let value_length_text_values = value_length_histogram.iter().map(|x| format!("({}, {})", x.0, x.1).to_string());
			code_text += &generate_code_parameter_text("pub const VALUE_LENGTH_HISTOGRAM: &[(u32, u32)] = &[\n".to_string(), "];\n".to_string(), value_length_text_values);

			{
				let filename = "trie_parameter_code.txt".to_string();

				let mut path = std::env::current_dir().expect("Cannot resolve current dir");
				path.push(filename);

				println!("Writing file: {}", path.display());

				let file = std::fs::OpenOptions::new()
					.create(true)
					.write(true)
					.truncate(true)
					.open(path.as_path()).expect("Failed to open file");

				let mut writer = std::io::BufWriter::new(file);

				writer.write_all(code_text.as_bytes()).expect("Unable to write data");
			}
		}

		Ok(TrieInfoResult {
			block_hash: block_hash,
			block_number: block_number,
			num_blocks_processed: num_blocks_processed,
			num_nodes: process_node_data.num_nodes,
			num_inline_nodes: process_node_data.num_inline_nodes,
			num_inline_leaf_nodes: process_node_data.num_inline_leaf_nodes,
			num_inline_branch_nodes: process_node_data.num_inline_branch_nodes,
			average_num_new_nodes: process_node_data.average_num_new_nodes,
			num_values: process_node_data.num_values,
			num_leaf_values: process_node_data.num_leaf_values,
			num_branch_values: process_node_data.num_branch_values,
			num_inline_values: process_node_data.num_inline_values,
			num_node_values: process_node_data.num_node_values,
			node_type_count: process_node_data.node_type_count,
			child_count_histogram: process_node_data.child_count_histogram,
			reference_count_histogram,
			depth_histogram: depth_histogram,
			depth_child_count_histograms: depth_child_count_histograms,
			key_length_histogram: key_length_histogram,
			value_length_histogram: value_length_histogram,
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
