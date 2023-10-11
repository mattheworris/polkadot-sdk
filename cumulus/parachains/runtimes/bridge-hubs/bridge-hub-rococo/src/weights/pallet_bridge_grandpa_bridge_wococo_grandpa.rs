// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Autogenerated weights for `pallet_bridge_grandpa`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-07-31, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `runner-ynta1nyy-project-238-concurrent-0`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! EXECUTION: ``, WASM-EXECUTION: `Compiled`, CHAIN: `Some("bridge-hub-rococo-dev")`, DB CACHE: 1024

// Executed Command:
// ./target/production/polkadot-parachain
// benchmark
// pallet
// --chain=bridge-hub-rococo-dev
// --wasm-execution=compiled
// --pallet=pallet_bridge_grandpa
// --no-storage-info
// --no-median-slopes
// --no-min-squares
// --extrinsic=*
// --steps=50
// --repeat=20
// --json
// --header=./file_header.txt
// --output=./parachains/runtimes/bridge-hubs/bridge-hub-rococo/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_bridge_grandpa`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_bridge_grandpa::WeightInfo for WeightInfo<T> {
	/// Storage: `BridgeWococoGrandpa::PalletOperatingMode` (r:1 w:0)
	/// Proof: `BridgeWococoGrandpa::PalletOperatingMode` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// Storage: `BridgeWococoGrandpa::BestFinalized` (r:1 w:1)
	/// Proof: `BridgeWococoGrandpa::BestFinalized` (`max_values`: Some(1), `max_size`: Some(36), added: 531, mode: `MaxEncodedLen`)
	/// Storage: `BridgeWococoGrandpa::CurrentAuthoritySet` (r:1 w:0)
	/// Proof: `BridgeWococoGrandpa::CurrentAuthoritySet` (`max_values`: Some(1), `max_size`: Some(50250), added: 50745, mode: `MaxEncodedLen`)
	/// Storage: `BridgeWococoGrandpa::ImportedHashesPointer` (r:1 w:1)
	/// Proof: `BridgeWococoGrandpa::ImportedHashesPointer` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	/// Storage: `BridgeWococoGrandpa::ImportedHashes` (r:1 w:1)
	/// Proof: `BridgeWococoGrandpa::ImportedHashes` (`max_values`: Some(1024), `max_size`: Some(36), added: 1521, mode: `MaxEncodedLen`)
	/// Storage: `BridgeWococoGrandpa::ImportedHeaders` (r:0 w:2)
	/// Proof: `BridgeWococoGrandpa::ImportedHeaders` (`max_values`: Some(1024), `max_size`: Some(68), added: 1553, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[1, 838]`.
	/// The range of component `v` is `[50, 100]`.
	/// The range of component `p` is `[1, 838]`.
	/// The range of component `v` is `[50, 100]`.
	fn submit_finality_proof(p: u32, v: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `268 + p * (60 ±0)`
		//  Estimated: `51735`
		// Minimum execution time: 260_423_000 picoseconds.
		Weight::from_parts(46_213_879, 0)
			.saturating_add(Weight::from_parts(0, 51735))
			// Standard Error: 4_794
			.saturating_add(Weight::from_parts(55_195_440, 0).saturating_mul(p.into()))
			// Standard Error: 79_973
			.saturating_add(Weight::from_parts(1_710_302, 0).saturating_mul(v.into()))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(5))
	}
}
