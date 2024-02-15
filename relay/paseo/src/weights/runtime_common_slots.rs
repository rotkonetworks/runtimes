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

//! Autogenerated weights for `runtime_common::slots`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-12-18, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ggwpez-ref-hw`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("../polkadot-chain-spec.json")`, DB CACHE: 1024

// Executed Command:
// ../polkadot-sdk/target/production/polkadot
// benchmark
// pallet
// --chain=../polkadot-chain-spec.json
// --steps
// 50
// --repeat
// 20
// --pallet=runtime_common::slots
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output
// ./polkadot-weights/
// --header
// ./file_header.txt

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `runtime_common::slots`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> runtime_common::slots::WeightInfo for WeightInfo<T> {
	/// Storage: `Slots::Leases` (r:1 w:1)
	/// Proof: `Slots::Leases` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn force_lease() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `254`
		//  Estimated: `3719`
		// Minimum execution time: 25_832_000 picoseconds.
		Weight::from_parts(27_085_000, 0)
			.saturating_add(Weight::from_parts(0, 3719))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Paras::Parachains` (r:1 w:0)
	/// Proof: `Paras::Parachains` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Slots::Leases` (r:101 w:100)
	/// Proof: `Slots::Leases` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ParaLifecycles` (r:200 w:200)
	/// Proof: `Paras::ParaLifecycles` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ActionsQueue` (r:1 w:1)
	/// Proof: `Paras::ActionsQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `c` is `[0, 100]`.
	/// The range of component `t` is `[0, 100]`.
	fn manage_lease_period_start(c: u32, t: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `557 + c * (20 ±0) + t * (234 ±0)`
		//  Estimated: `4028 + c * (2496 ±0) + t * (2709 ±0)`
		// Minimum execution time: 709_290_000 picoseconds.
		Weight::from_parts(721_642_000, 0)
			.saturating_add(Weight::from_parts(0, 4028))
			// Standard Error: 86_997
			.saturating_add(Weight::from_parts(2_876_796, 0).saturating_mul(c.into()))
			// Standard Error: 86_997
			.saturating_add(Weight::from_parts(9_088_187, 0).saturating_mul(t.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(c.into())))
			.saturating_add(T::DbWeight::get().reads((2_u64).saturating_mul(t.into())))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(c.into())))
			.saturating_add(T::DbWeight::get().writes((2_u64).saturating_mul(t.into())))
			.saturating_add(Weight::from_parts(0, 2496).saturating_mul(c.into()))
			.saturating_add(Weight::from_parts(0, 2709).saturating_mul(t.into()))
	}
	/// Storage: `Slots::Leases` (r:1 w:1)
	/// Proof: `Slots::Leases` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:8 w:8)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn clear_all_leases() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2726`
		//  Estimated: `21814`
		// Minimum execution time: 135_040_000 picoseconds.
		Weight::from_parts(146_076_000, 0)
			.saturating_add(Weight::from_parts(0, 21814))
			.saturating_add(T::DbWeight::get().reads(9))
			.saturating_add(T::DbWeight::get().writes(9))
	}
	/// Storage: `Slots::Leases` (r:1 w:0)
	/// Proof: `Slots::Leases` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ParaLifecycles` (r:1 w:1)
	/// Proof: `Paras::ParaLifecycles` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ActionsQueue` (r:1 w:1)
	/// Proof: `Paras::ActionsQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn trigger_onboard() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `550`
		//  Estimated: `4015`
		// Minimum execution time: 28_188_000 picoseconds.
		Weight::from_parts(34_661_000, 0)
			.saturating_add(Weight::from_parts(0, 4015))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(2))
	}
}
