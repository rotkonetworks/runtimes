// Copyright (C) Parity Technologies and the various Polkadot contributors, see Contributions.md
// for a list of specific contributors.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Autogenerated weights for `pallet_proxy`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2024-02-17, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `p-ch-hmb-vm-vapas-002`, CPU: `Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("./paseo-chain-spec.json")`, DB CACHE: 1024

// Executed Command:
// ./target/production/polkadot
// benchmark
// pallet
// --chain=./paseo-chain-spec.json
// --steps=50
// --repeat=20
// --pallet=pallet_proxy
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./paseo-weights/
// --header=./file_header.txt

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_proxy`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_proxy::WeightInfo for WeightInfo<T> {
	/// Storage: `Proxy::Proxies` (r:1 w:0)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[1, 31]`.
	fn proxy(_p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `89 + p * (37 ±0)`
		//  Estimated: `4706`
		// Minimum execution time: 13_452_000 picoseconds.
		Weight::from_parts(16_097_177, 0)
			.saturating_add(Weight::from_parts(0, 4706))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:0)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// Storage: `Proxy::Announcements` (r:1 w:1)
	/// Proof: `Proxy::Announcements` (`max_values`: None, `max_size`: Some(2233), added: 4708, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn proxy_announced(a: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `416 + a * (68 ±0) + p * (37 ±0)`
		//  Estimated: `5698`
		// Minimum execution time: 38_678_000 picoseconds.
		Weight::from_parts(38_002_542, 0)
			.saturating_add(Weight::from_parts(0, 5698))
			// Standard Error: 15_091
			.saturating_add(Weight::from_parts(171_490, 0).saturating_mul(a.into()))
			// Standard Error: 15_592
			.saturating_add(Weight::from_parts(130_713, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Proxy::Announcements` (r:1 w:1)
	/// Proof: `Proxy::Announcements` (`max_values`: None, `max_size`: Some(2233), added: 4708, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn remove_announcement(a: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `331 + a * (68 ±0)`
		//  Estimated: `5698`
		// Minimum execution time: 24_121_000 picoseconds.
		Weight::from_parts(26_734_045, 0)
			.saturating_add(Weight::from_parts(0, 5698))
			// Standard Error: 4_546
			.saturating_add(Weight::from_parts(88_770, 0).saturating_mul(a.into()))
			// Standard Error: 4_697
			.saturating_add(Weight::from_parts(7_143, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Proxy::Announcements` (r:1 w:1)
	/// Proof: `Proxy::Announcements` (`max_values`: None, `max_size`: Some(2233), added: 4708, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn reject_announcement(a: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `331 + a * (68 ±0)`
		//  Estimated: `5698`
		// Minimum execution time: 23_443_000 picoseconds.
		Weight::from_parts(23_785_662, 0)
			.saturating_add(Weight::from_parts(0, 5698))
			// Standard Error: 8_777
			.saturating_add(Weight::from_parts(172_749, 0).saturating_mul(a.into()))
			// Standard Error: 9_069
			.saturating_add(Weight::from_parts(61_486, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:0)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// Storage: `Proxy::Announcements` (r:1 w:1)
	/// Proof: `Proxy::Announcements` (`max_values`: None, `max_size`: Some(2233), added: 4708, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn announce(a: u32, p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `348 + a * (68 ±0) + p * (37 ±0)`
		//  Estimated: `5698`
		// Minimum execution time: 34_551_000 picoseconds.
		Weight::from_parts(34_728_693, 0)
			.saturating_add(Weight::from_parts(0, 5698))
			// Standard Error: 11_759
			.saturating_add(Weight::from_parts(198_085, 0).saturating_mul(a.into()))
			// Standard Error: 12_150
			.saturating_add(Weight::from_parts(31_273, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:1)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[1, 31]`.
	fn add_proxy(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `89 + p * (37 ±0)`
		//  Estimated: `4706`
		// Minimum execution time: 22_738_000 picoseconds.
		Weight::from_parts(23_426_323, 0)
			.saturating_add(Weight::from_parts(0, 4706))
			// Standard Error: 1_007
			.saturating_add(Weight::from_parts(48_681, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:1)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[1, 31]`.
	fn remove_proxy(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `89 + p * (37 ±0)`
		//  Estimated: `4706`
		// Minimum execution time: 22_499_000 picoseconds.
		Weight::from_parts(23_643_958, 0)
			.saturating_add(Weight::from_parts(0, 4706))
			// Standard Error: 1_765
			.saturating_add(Weight::from_parts(50_161, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:1)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[1, 31]`.
	fn remove_proxies(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `89 + p * (37 ±0)`
		//  Estimated: `4706`
		// Minimum execution time: 21_158_000 picoseconds.
		Weight::from_parts(21_983_601, 0)
			.saturating_add(Weight::from_parts(0, 4706))
			// Standard Error: 1_505
			.saturating_add(Weight::from_parts(50_322, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:1)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[1, 31]`.
	fn create_pure(_p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `101`
		//  Estimated: `4706`
		// Minimum execution time: 23_646_000 picoseconds.
		Weight::from_parts(24_989_761, 0)
			.saturating_add(Weight::from_parts(0, 4706))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Proxy::Proxies` (r:1 w:1)
	/// Proof: `Proxy::Proxies` (`max_values`: None, `max_size`: Some(1241), added: 3716, mode: `MaxEncodedLen`)
	/// The range of component `p` is `[0, 30]`.
	fn kill_pure(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `126 + p * (37 ±0)`
		//  Estimated: `4706`
		// Minimum execution time: 22_150_000 picoseconds.
		Weight::from_parts(22_367_724, 0)
			.saturating_add(Weight::from_parts(0, 4706))
			// Standard Error: 7_381
			.saturating_add(Weight::from_parts(129_420, 0).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
