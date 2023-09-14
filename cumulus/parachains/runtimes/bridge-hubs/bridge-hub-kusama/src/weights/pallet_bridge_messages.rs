// Copyright Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! Autogenerated weights for `pallet_bridge_messages`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-05-09, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `bm3`, CPU: `Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("bridge-hub-kusama-dev"), DB CACHE: 1024

// Executed Command:
// target/production/polkadot-parachain
// benchmark
// pallet
// --steps=50
// --repeat=20
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --json-file=/var/lib/gitlab-runner/builds/zyw4fam_/0/parity/mirrors/cumulus/.git/.artifacts/bench.json
// --pallet=pallet_bridge_messages
// --chain=bridge-hub-kusama-dev
// --header=./file_header.txt
// --output=./parachains/runtimes/bridge-hubs/bridge-hub-kusama/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_bridge_messages`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_bridge_messages::WeightInfo for WeightInfo<T> {
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages InboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages InboundLanes (max_values: None, max_size: Some(49180), added: 51655, mode: MaxEncodedLen)
	/// Storage: ParachainInfo ParachainId (r:1 w:0)
	/// Proof: ParachainInfo ParachainId (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	fn receive_single_message_proof() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `403`
		//  Estimated: `52645`
		// Minimum execution time: 44_142_000 picoseconds.
		Weight::from_parts(44_925_000, 0)
			.saturating_add(Weight::from_parts(0, 52645))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages InboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages InboundLanes (max_values: None, max_size: Some(49180), added: 51655, mode: MaxEncodedLen)
	/// Storage: ParachainInfo ParachainId (r:1 w:0)
	/// Proof: ParachainInfo ParachainId (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	fn receive_two_messages_proof() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `403`
		//  Estimated: `52645`
		// Minimum execution time: 54_901_000 picoseconds.
		Weight::from_parts(55_357_000, 0)
			.saturating_add(Weight::from_parts(0, 52645))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages InboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages InboundLanes (max_values: None, max_size: Some(49180), added: 51655, mode: MaxEncodedLen)
	/// Storage: ParachainInfo ParachainId (r:1 w:0)
	/// Proof: ParachainInfo ParachainId (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	fn receive_single_message_proof_with_outbound_lane_state() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `403`
		//  Estimated: `52645`
		// Minimum execution time: 49_037_000 picoseconds.
		Weight::from_parts(49_616_000, 0)
			.saturating_add(Weight::from_parts(0, 52645))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages InboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages InboundLanes (max_values: None, max_size: Some(49180), added: 51655, mode: MaxEncodedLen)
	fn receive_single_message_proof_1_kb() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `372`
		//  Estimated: `52645`
		// Minimum execution time: 42_180_000 picoseconds.
		Weight::from_parts(42_666_000, 0)
			.saturating_add(Weight::from_parts(0, 52645))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages InboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages InboundLanes (max_values: None, max_size: Some(49180), added: 51655, mode: MaxEncodedLen)
	fn receive_single_message_proof_16_kb() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `372`
		//  Estimated: `52645`
		// Minimum execution time: 69_307_000 picoseconds.
		Weight::from_parts(69_871_000, 0)
			.saturating_add(Weight::from_parts(0, 52645))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages OutboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages OutboundLanes (max_values: Some(1), max_size: Some(44), added: 539, mode: MaxEncodedLen)
	/// Storage: unknown `0x6e0a18b62a1de81c5f519181cc611e18` (r:1 w:0)
	/// Proof Skipped: unknown `0x6e0a18b62a1de81c5f519181cc611e18` (r:1 w:0)
	/// Storage: BridgeRelayers RelayerRewards (r:1 w:1)
	/// Proof: BridgeRelayers RelayerRewards (max_values: None, max_size: Some(73), added: 2548, mode: MaxEncodedLen)
	fn receive_delivery_proof_for_single_message() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `376`
		//  Estimated: `3841`
		// Minimum execution time: 33_354_000 picoseconds.
		Weight::from_parts(34_244_000, 0)
			.saturating_add(Weight::from_parts(0, 3841))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages OutboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages OutboundLanes (max_values: Some(1), max_size: Some(44), added: 539, mode: MaxEncodedLen)
	/// Storage: unknown `0x6e0a18b62a1de81c5f519181cc611e18` (r:1 w:0)
	/// Proof Skipped: unknown `0x6e0a18b62a1de81c5f519181cc611e18` (r:1 w:0)
	/// Storage: BridgeRelayers RelayerRewards (r:1 w:1)
	/// Proof: BridgeRelayers RelayerRewards (max_values: None, max_size: Some(73), added: 2548, mode: MaxEncodedLen)
	fn receive_delivery_proof_for_two_messages_by_single_relayer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `376`
		//  Estimated: `3841`
		// Minimum execution time: 33_264_000 picoseconds.
		Weight::from_parts(33_675_000, 0)
			.saturating_add(Weight::from_parts(0, 3841))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages OutboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages OutboundLanes (max_values: Some(1), max_size: Some(44), added: 539, mode: MaxEncodedLen)
	/// Storage: unknown `0x6e0a18b62a1de81c5f519181cc611e18` (r:1 w:0)
	/// Proof Skipped: unknown `0x6e0a18b62a1de81c5f519181cc611e18` (r:1 w:0)
	/// Storage: BridgeRelayers RelayerRewards (r:2 w:2)
	/// Proof: BridgeRelayers RelayerRewards (max_values: None, max_size: Some(73), added: 2548, mode: MaxEncodedLen)
	fn receive_delivery_proof_for_two_messages_by_two_relayers() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `376`
		//  Estimated: `6086`
		// Minimum execution time: 35_608_000 picoseconds.
		Weight::from_parts(36_142_000, 0)
			.saturating_add(Weight::from_parts(0, 6086))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: BridgePolkadotMessages PalletOperatingMode (r:1 w:0)
	/// Proof: BridgePolkadotMessages PalletOperatingMode (max_values: Some(1), max_size: Some(2), added: 497, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotParachain ImportedParaHeads (r:1 w:0)
	/// Proof: BridgePolkadotParachain ImportedParaHeads (max_values: Some(64), max_size: Some(196), added: 1186, mode: MaxEncodedLen)
	/// Storage: BridgePolkadotMessages InboundLanes (r:1 w:1)
	/// Proof: BridgePolkadotMessages InboundLanes (max_values: None, max_size: Some(49180), added: 51655, mode: MaxEncodedLen)
	/// Storage: ParachainInfo ParachainId (r:1 w:0)
	/// Proof: ParachainInfo ParachainId (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	/// Storage: PolkadotXcm SupportedVersion (r:1 w:0)
	/// Proof Skipped: PolkadotXcm SupportedVersion (max_values: None, max_size: None, mode: Measured)
	/// Storage: PolkadotXcm VersionDiscoveryQueue (r:1 w:1)
	/// Proof Skipped: PolkadotXcm VersionDiscoveryQueue (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: PolkadotXcm SafeXcmVersion (r:1 w:0)
	/// Proof Skipped: PolkadotXcm SafeXcmVersion (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: ParachainSystem RelevantMessagingState (r:1 w:0)
	/// Proof Skipped: ParachainSystem RelevantMessagingState (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: XcmpQueue OutboundXcmpStatus (r:1 w:1)
	/// Proof Skipped: XcmpQueue OutboundXcmpStatus (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: XcmpQueue OutboundXcmpMessages (r:0 w:1)
	/// Proof Skipped: XcmpQueue OutboundXcmpMessages (max_values: None, max_size: None, mode: Measured)
	/// The range of component `i` is `[128, 2048]`.
	fn receive_single_message_proof_with_dispatch(i: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `634`
		//  Estimated: `52645`
		// Minimum execution time: 130_265_000 picoseconds.
		Weight::from_parts(100_110_870, 0)
			.saturating_add(Weight::from_parts(0, 52645))
			// Standard Error: 3_659
			.saturating_add(Weight::from_parts(547_474, 0).saturating_mul(i.into()))
			.saturating_add(T::DbWeight::get().reads(9))
			.saturating_add(T::DbWeight::get().writes(4))
	}
}