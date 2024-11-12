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

//! Autogenerated weights for `runtime_parachains::paras`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2024-08-15, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ggwpez-ref-hw`, CPU: `AMD EPYC 7232P 8-Core Processor`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("./paseo-chain-spec.json")`, DB CACHE: 1024

// Executed Command:
// ./target/production/paseo
// benchmark
// pallet
// --chain=./paseo-chain-spec.json
// --steps=50
// --repeat=20
// --pallet=runtime_parachains::paras
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

/// Weight functions for `runtime_parachains::paras`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> runtime_parachains::paras::WeightInfo for WeightInfo<T> {
	/// Storage: `Paras::CodeByHashRefs` (r:1 w:1)
	/// Proof: `Paras::CodeByHashRefs` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::CurrentCodeHash` (r:1 w:1)
	/// Proof: `Paras::CurrentCodeHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Digest` (r:1 w:1)
	/// Proof: `System::Digest` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PastCodeMeta` (r:1 w:1)
	/// Proof: `Paras::PastCodeMeta` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PastCodePruning` (r:1 w:1)
	/// Proof: `Paras::PastCodePruning` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PastCodeHash` (r:0 w:1)
	/// Proof: `Paras::PastCodeHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::CodeByHash` (r:0 w:1)
	/// Proof: `Paras::CodeByHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `c` is `[9, 3145728]`.
	fn force_set_current_code(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `8309`
		//  Estimated: `11774`
		// Minimum execution time: 35_820_000 picoseconds.
		Weight::from_parts(36_241_000, 0)
			.saturating_add(Weight::from_parts(0, 11774))
			// Standard Error: 5
			.saturating_add(Weight::from_parts(2_456, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Paras::Heads` (r:0 w:1)
	/// Proof: `Paras::Heads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `s` is `[9, 1048576]`.
	fn force_set_current_head(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 6_990_000 picoseconds.
		Weight::from_parts(7_230_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			// Standard Error: 3
			.saturating_add(Weight::from_parts(932, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Paras::MostRecentContext` (r:0 w:1)
	/// Proof: `Paras::MostRecentContext` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn force_set_most_recent_context() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_590_000 picoseconds.
		Weight::from_parts(3_740_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Paras::FutureCodeHash` (r:1 w:1)
	/// Proof: `Paras::FutureCodeHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::CurrentCodeHash` (r:1 w:0)
	/// Proof: `Paras::CurrentCodeHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::UpgradeCooldowns` (r:1 w:1)
	/// Proof: `Paras::UpgradeCooldowns` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::CodeByHash` (r:1 w:1)
	/// Proof: `Paras::CodeByHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::ActiveValidatorKeys` (r:1 w:0)
	/// Proof: `ParasShared::ActiveValidatorKeys` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteList` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteList` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::CodeByHashRefs` (r:1 w:1)
	/// Proof: `Paras::CodeByHashRefs` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::UpgradeRestrictionSignal` (r:0 w:1)
	/// Proof: `Paras::UpgradeRestrictionSignal` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `c` is `[9, 3145728]`.
	fn force_schedule_code_upgrade(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `8489`
		//  Estimated: `11954`
		// Minimum execution time: 48_421_000 picoseconds.
		Weight::from_parts(48_750_000, 0)
			.saturating_add(Weight::from_parts(0, 11954))
			// Standard Error: 4
			.saturating_add(Weight::from_parts(2_434, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(8))
			.saturating_add(T::DbWeight::get().writes(7))
	}
	/// Storage: `Paras::FutureCodeUpgrades` (r:1 w:0)
	/// Proof: `Paras::FutureCodeUpgrades` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Registrar::Paras` (r:1 w:0)
	/// Proof: `Registrar::Paras` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::Heads` (r:0 w:1)
	/// Proof: `Paras::Heads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::UpgradeGoAheadSignal` (r:0 w:1)
	/// Proof: `Paras::UpgradeGoAheadSignal` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::MostRecentContext` (r:0 w:1)
	/// Proof: `Paras::MostRecentContext` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `s` is `[9, 1048576]`.
	fn force_note_new_head(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `337`
		//  Estimated: `3802`
		// Minimum execution time: 18_611_000 picoseconds.
		Weight::from_parts(18_790_000, 0)
			.saturating_add(Weight::from_parts(0, 3802))
			// Standard Error: 3
			.saturating_add(Weight::from_parts(944, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ActionsQueue` (r:1 w:1)
	/// Proof: `Paras::ActionsQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn force_queue_action() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `4316`
		//  Estimated: `7781`
		// Minimum execution time: 20_500_000 picoseconds.
		Weight::from_parts(20_740_000, 0)
			.saturating_add(Weight::from_parts(0, 7781))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteList` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteList` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ActionsQueue` (r:1 w:1)
	/// Proof: `Paras::ActionsQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// The range of component `c` is `[9, 3145728]`.
	fn add_trusted_validation_code(c: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `683`
		//  Estimated: `4148`
		// Minimum execution time: 76_131_000 picoseconds.
		Weight::from_parts(76_980_000, 0)
			.saturating_add(Weight::from_parts(0, 4148))
			// Standard Error: 2
			.saturating_add(Weight::from_parts(1_823, 0).saturating_mul(c.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `Paras::CodeByHashRefs` (r:1 w:0)
	/// Proof: `Paras::CodeByHashRefs` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::CodeByHash` (r:0 w:1)
	/// Proof: `Paras::CodeByHash` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn poke_unused_validation_code() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `28`
		//  Estimated: `3493`
		// Minimum execution time: 6_360_000 picoseconds.
		Weight::from_parts(6_650_000, 0)
			.saturating_add(Weight::from_parts(0, 3493))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ParasShared::ActiveValidatorKeys` (r:1 w:0)
	/// Proof: `ParasShared::ActiveValidatorKeys` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn include_pvf_check_statement() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `26706`
		//  Estimated: `30171`
		// Minimum execution time: 109_621_000 picoseconds.
		Weight::from_parts(112_091_000, 0)
			.saturating_add(Weight::from_parts(0, 30171))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ParasShared::ActiveValidatorKeys` (r:1 w:0)
	/// Proof: `ParasShared::ActiveValidatorKeys` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteList` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteList` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::UpcomingUpgrades` (r:1 w:1)
	/// Proof: `Paras::UpcomingUpgrades` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `System::Digest` (r:1 w:1)
	/// Proof: `System::Digest` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::FutureCodeUpgrades` (r:0 w:100)
	/// Proof: `Paras::FutureCodeUpgrades` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn include_pvf_check_statement_finalize_upgrade_accept() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `27360`
		//  Estimated: `30825`
		// Minimum execution time: 758_106_000 picoseconds.
		Weight::from_parts(765_035_000, 0)
			.saturating_add(Weight::from_parts(0, 30825))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(104))
	}
	/// Storage: `ParasShared::ActiveValidatorKeys` (r:1 w:0)
	/// Proof: `ParasShared::ActiveValidatorKeys` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn include_pvf_check_statement_finalize_upgrade_reject() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `27338`
		//  Estimated: `30803`
		// Minimum execution time: 106_491_000 picoseconds.
		Weight::from_parts(108_080_000, 0)
			.saturating_add(Weight::from_parts(0, 30803))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ParasShared::ActiveValidatorKeys` (r:1 w:0)
	/// Proof: `ParasShared::ActiveValidatorKeys` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteList` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteList` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::ActionsQueue` (r:1 w:1)
	/// Proof: `Paras::ActionsQueue` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn include_pvf_check_statement_finalize_onboarding_accept() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `26728`
		//  Estimated: `30193`
		// Minimum execution time: 598_735_000 picoseconds.
		Weight::from_parts(606_214_000, 0)
			.saturating_add(Weight::from_parts(0, 30193))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ParasShared::ActiveValidatorKeys` (r:1 w:0)
	/// Proof: `ParasShared::ActiveValidatorKeys` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `ParasShared::CurrentSessionIndex` (r:1 w:0)
	/// Proof: `ParasShared::CurrentSessionIndex` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	/// Storage: `Paras::PvfActiveVoteMap` (r:1 w:1)
	/// Proof: `Paras::PvfActiveVoteMap` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn include_pvf_check_statement_finalize_onboarding_reject() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `26706`
		//  Estimated: `30171`
		// Minimum execution time: 103_901_000 picoseconds.
		Weight::from_parts(106_241_000, 0)
			.saturating_add(Weight::from_parts(0, 30171))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
