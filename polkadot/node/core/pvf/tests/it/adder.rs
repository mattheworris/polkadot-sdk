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

use super::TestHost;
use adder::{hash_state, BlockData, HeadData};
use parity_scale_codec::{Decode, Encode};
use polkadot_parachain_primitives::primitives::{
	BlockData as GenericBlockData, HeadData as GenericHeadData, RelayChainBlockNumber,
	ValidationParams,
};

#[tokio::test]
async fn execute_good_block_on_parent() {
	let parent_head = HeadData { number: 0, parent_hash: [0; 32], post_state: hash_state(0) };

	let block_data = BlockData { state: 0, add: 512 };

	let host = TestHost::new().await;

	let ret = host
		.validate_candidate(
			adder::wasm_binary_unwrap(),
			ValidationParams {
				parent_head: GenericHeadData(parent_head.encode()),
				block_data: GenericBlockData(block_data.encode()),
				relay_parent_number: 1,
				relay_parent_storage_root: Default::default(),
			},
			Default::default(),
		)
		.await
		.unwrap();

	let new_head = HeadData::decode(&mut &ret.head_data.0[..]).unwrap();

	assert_eq!(new_head.number, 1);
	assert_eq!(new_head.parent_hash, parent_head.hash());
	assert_eq!(new_head.post_state, hash_state(512));
}

#[tokio::test]
async fn execute_good_chain_on_parent() {
	let mut parent_hash = [0; 32];
	let mut last_state = 0;

	let host = TestHost::new().await;

	for (number, add) in (0..10).enumerate() {
		let parent_head =
			HeadData { number: number as u64, parent_hash, post_state: hash_state(last_state) };

		let block_data = BlockData { state: last_state, add };

		let ret = host
			.validate_candidate(
				adder::wasm_binary_unwrap(),
				ValidationParams {
					parent_head: GenericHeadData(parent_head.encode()),
					block_data: GenericBlockData(block_data.encode()),
					relay_parent_number: number as RelayChainBlockNumber + 1,
					relay_parent_storage_root: Default::default(),
				},
				Default::default(),
			)
			.await
			.unwrap();

		let new_head = HeadData::decode(&mut &ret.head_data.0[..]).unwrap();

		assert_eq!(new_head.number, number as u64 + 1);
		assert_eq!(new_head.parent_hash, parent_head.hash());
		assert_eq!(new_head.post_state, hash_state(last_state + add));

		parent_hash = new_head.hash();
		last_state += add;
	}
}

#[tokio::test]
async fn execute_bad_block_on_parent() {
	let parent_head = HeadData { number: 0, parent_hash: [0; 32], post_state: hash_state(0) };

	let block_data = BlockData {
		state: 256, // start state is wrong.
		add: 256,
	};

	let host = TestHost::new().await;

	let _err = host
		.validate_candidate(
			adder::wasm_binary_unwrap(),
			ValidationParams {
				parent_head: GenericHeadData(parent_head.encode()),
				block_data: GenericBlockData(block_data.encode()),
				relay_parent_number: 1,
				relay_parent_storage_root: Default::default(),
			},
			Default::default(),
		)
		.await
		.unwrap_err();
}

#[tokio::test]
async fn stress_spawn() {
	let host = std::sync::Arc::new(TestHost::new().await);

	async fn execute(host: std::sync::Arc<TestHost>) {
		let parent_head = HeadData { number: 0, parent_hash: [0; 32], post_state: hash_state(0) };
		let block_data = BlockData { state: 0, add: 512 };
		let ret = host
			.validate_candidate(
				adder::wasm_binary_unwrap(),
				ValidationParams {
					parent_head: GenericHeadData(parent_head.encode()),
					block_data: GenericBlockData(block_data.encode()),
					relay_parent_number: 1,
					relay_parent_storage_root: Default::default(),
				},
				Default::default(),
			)
			.await
			.unwrap();

		let new_head = HeadData::decode(&mut &ret.head_data.0[..]).unwrap();

		assert_eq!(new_head.number, 1);
		assert_eq!(new_head.parent_hash, parent_head.hash());
		assert_eq!(new_head.post_state, hash_state(512));
	}

	futures::future::join_all((0..100).map(|_| execute(host.clone()))).await;
}

// With one worker, run multiple execution jobs serially. They should not conflict.
#[tokio::test]
async fn execute_can_run_serially() {
	let host = std::sync::Arc::new(
		TestHost::new_with_config(|cfg| {
			cfg.execute_workers_max_num = 1;
		})
		.await,
	);

	async fn execute(host: std::sync::Arc<TestHost>) {
		let parent_head = HeadData { number: 0, parent_hash: [0; 32], post_state: hash_state(0) };
		let block_data = BlockData { state: 0, add: 512 };
		let ret = host
			.validate_candidate(
				adder::wasm_binary_unwrap(),
				ValidationParams {
					parent_head: GenericHeadData(parent_head.encode()),
					block_data: GenericBlockData(block_data.encode()),
					relay_parent_number: 1,
					relay_parent_storage_root: Default::default(),
				},
				Default::default(),
			)
			.await
			.unwrap();

		let new_head = HeadData::decode(&mut &ret.head_data.0[..]).unwrap();

		assert_eq!(new_head.number, 1);
		assert_eq!(new_head.parent_hash, parent_head.hash());
		assert_eq!(new_head.post_state, hash_state(512));
	}

	futures::future::join_all((0..5).map(|_| execute(host.clone()))).await;
}
