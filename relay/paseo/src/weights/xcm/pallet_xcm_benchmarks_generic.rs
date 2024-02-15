// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Paseo.

// Paseo is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Paseo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Paseo.  If not, see <http://www.gnu.org/licenses/>.

//! Autogenerated weights for `pallet_xcm_benchmarks::generic`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-04-14, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("polkadot-dev"), DB CACHE: 1024

// Executed Command:
// ./target/production/polkadot
// benchmark
// pallet
// --steps=50
// --repeat=20
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --pallet=pallet_xcm_benchmarks::generic
// --chain=polkadot-dev
// --header=./file_header.txt
// --template=./xcm/pallet-xcm-benchmarks/template.hbs
// --output=./runtime/polkadot/src/weights/xcm/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weights for `pallet_xcm_benchmarks::generic`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo<T> {
	// Storage: Configuration ActiveConfig (r:1 w:0)
	// Proof Skipped: Configuration ActiveConfig (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SupportedVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SupportedVersion (max_values: None, max_size: None, mode: Measured)
	// Storage: XcmPallet VersionDiscoveryQueue (r:1 w:1)
	// Proof Skipped: XcmPallet VersionDiscoveryQueue (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SafeXcmVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SafeXcmVersion (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueues (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueues (max_values: None, max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueueHeads (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueueHeads (max_values: None, max_size: None, mode: Measured)
	pub fn report_holding() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `17934`
		// Minimum execution time: 33_813_000 picoseconds.
		Weight::from_parts(34_357_000, 17934)
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	pub fn buy_execution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_067_000 picoseconds.
		Weight::from_parts(3_153_000, 0)
	}
	// Storage: XcmPallet Queries (r:1 w:0)
	// Proof Skipped: XcmPallet Queries (max_values: None, max_size: None, mode: Measured)
	pub fn query_response() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `169`
		//  Estimated: `3634`
		// Minimum execution time: 12_236_000 picoseconds.
		Weight::from_parts(12_725_000, 3634)
			.saturating_add(T::DbWeight::get().reads(1))
	}
	pub fn transact() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 13_193_000 picoseconds.
		Weight::from_parts(13_427_000, 0)
	}
	pub fn refund_surplus() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_393_000 picoseconds.
		Weight::from_parts(3_464_000, 0)
	}
	pub fn set_error_handler() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_955_000 picoseconds.
		Weight::from_parts(3_068_000, 0)
	}
	pub fn set_appendix() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_004_000 picoseconds.
		Weight::from_parts(3_107_000, 0)
	}
	pub fn clear_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_981_000 picoseconds.
		Weight::from_parts(3_039_000, 0)
	}
	pub fn descend_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_814_000 picoseconds.
		Weight::from_parts(3_897_000, 0)
	}
	pub fn clear_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_921_000 picoseconds.
		Weight::from_parts(3_010_000, 0)
	}
	// Storage: Configuration ActiveConfig (r:1 w:0)
	// Proof Skipped: Configuration ActiveConfig (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SupportedVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SupportedVersion (max_values: None, max_size: None, mode: Measured)
	// Storage: XcmPallet VersionDiscoveryQueue (r:1 w:1)
	// Proof Skipped: XcmPallet VersionDiscoveryQueue (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SafeXcmVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SafeXcmVersion (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueues (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueues (max_values: None, max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueueHeads (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueueHeads (max_values: None, max_size: None, mode: Measured)
	pub fn report_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `17934`
		// Minimum execution time: 28_324_000 picoseconds.
		Weight::from_parts(28_690_000, 17934)
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	// Storage: XcmPallet AssetTraps (r:1 w:1)
	// Proof Skipped: XcmPallet AssetTraps (max_values: None, max_size: None, mode: Measured)
	pub fn claim_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `226`
		//  Estimated: `3691`
		// Minimum execution time: 16_430_000 picoseconds.
		Weight::from_parts(16_774_000, 3691)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	pub fn trap() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_916_000 picoseconds.
		Weight::from_parts(3_035_000, 0)
	}
	// Storage: XcmPallet VersionNotifyTargets (r:1 w:1)
	// Proof Skipped: XcmPallet VersionNotifyTargets (max_values: None, max_size: None, mode: Measured)
	// Storage: Configuration ActiveConfig (r:1 w:0)
	// Proof Skipped: Configuration ActiveConfig (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SupportedVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SupportedVersion (max_values: None, max_size: None, mode: Measured)
	// Storage: XcmPallet VersionDiscoveryQueue (r:1 w:1)
	// Proof Skipped: XcmPallet VersionDiscoveryQueue (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SafeXcmVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SafeXcmVersion (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueues (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueues (max_values: None, max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueueHeads (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueueHeads (max_values: None, max_size: None, mode: Measured)
	pub fn subscribe_version() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `21913`
		// Minimum execution time: 35_915_000 picoseconds.
		Weight::from_parts(36_519_000, 21913)
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	// Storage: XcmPallet VersionNotifyTargets (r:0 w:1)
	// Proof Skipped: XcmPallet VersionNotifyTargets (max_values: None, max_size: None, mode: Measured)
	pub fn unsubscribe_version() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 5_344_000 picoseconds.
		Weight::from_parts(5_487_000, 0)
			.saturating_add(T::DbWeight::get().writes(1))
	}
	pub fn burn_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 4_684_000 picoseconds.
		Weight::from_parts(4_801_000, 0)
	}
	pub fn expect_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_228_000 picoseconds.
		Weight::from_parts(3_325_000, 0)
	}
	pub fn expect_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_059_000 picoseconds.
		Weight::from_parts(3_153_000, 0)
	}
	pub fn expect_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_037_000 picoseconds.
		Weight::from_parts(3_128_000, 0)
	}
	pub fn expect_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_287_000 picoseconds.
		Weight::from_parts(3_360_000, 0)
	}
	// Storage: Configuration ActiveConfig (r:1 w:0)
	// Proof Skipped: Configuration ActiveConfig (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SupportedVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SupportedVersion (max_values: None, max_size: None, mode: Measured)
	// Storage: XcmPallet VersionDiscoveryQueue (r:1 w:1)
	// Proof Skipped: XcmPallet VersionDiscoveryQueue (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SafeXcmVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SafeXcmVersion (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueues (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueues (max_values: None, max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueueHeads (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueueHeads (max_values: None, max_size: None, mode: Measured)
	pub fn query_pallet() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `17934`
		// Minimum execution time: 35_467_000 picoseconds.
		Weight::from_parts(36_011_000, 17934)
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	pub fn expect_pallet() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 8_630_000 picoseconds.
		Weight::from_parts(8_870_000, 0)
	}
	// Storage: Configuration ActiveConfig (r:1 w:0)
	// Proof Skipped: Configuration ActiveConfig (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SupportedVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SupportedVersion (max_values: None, max_size: None, mode: Measured)
	// Storage: XcmPallet VersionDiscoveryQueue (r:1 w:1)
	// Proof Skipped: XcmPallet VersionDiscoveryQueue (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmPallet SafeXcmVersion (r:1 w:0)
	// Proof Skipped: XcmPallet SafeXcmVersion (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueues (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueues (max_values: None, max_size: None, mode: Measured)
	// Storage: Dmp DownwardMessageQueueHeads (r:1 w:1)
	// Proof Skipped: Dmp DownwardMessageQueueHeads (max_values: None, max_size: None, mode: Measured)
	pub fn report_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `514`
		//  Estimated: `17934`
		// Minimum execution time: 28_630_000 picoseconds.
		Weight::from_parts(29_085_000, 17934)
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	pub fn clear_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_997_000 picoseconds.
		Weight::from_parts(3_096_000, 0)
	}
	pub fn set_topic() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_984_000 picoseconds.
		Weight::from_parts(3_059_000, 0)
	}
	pub fn clear_topic() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_969_000 picoseconds.
		Weight::from_parts(3_006_000, 0)
	}
	pub fn set_fees_mode() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_045_000 picoseconds.
		Weight::from_parts(3_087_000, 0)
	}
	pub fn unpaid_execution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_141_000 picoseconds.
		Weight::from_parts(3_251_000, 0)
	}
}
