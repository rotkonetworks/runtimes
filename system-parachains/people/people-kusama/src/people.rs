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

use super::*;
use crate::xcm_config::LocationToAccountId;
use codec::{Decode, Encode, MaxEncodedLen};
use enumflags2::{bitflags, BitFlags};
use frame_support::{
	parameter_types, CloneNoBound, EqNoBound, PartialEqNoBound, RuntimeDebugNoBound,
};
use pallet_identity::{Data, IdentityInformationProvider};
use parachains_common::{impls::ToParentTreasury, DAYS};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{AccountIdConversion, Verify},
	RuntimeDebug,
};
use sp_std::prelude::*;

parameter_types! {
	//   27 | Min encoded size of `Registration`
	// - 10 | Min encoded size of `IdentityInfo`
	// -----|
	//   17 | Min size without `IdentityInfo` (accounted for in byte deposit)
	pub const BasicDeposit: Balance = system_para_deposit(1, 17);
	pub const ByteDeposit: Balance = system_para_deposit(0, 1);
	pub const SubAccountDeposit: Balance = system_para_deposit(1, 53);
	pub RelayTreasuryAccount: AccountId =
		parachains_common::TREASURY_PALLET_ID.into_account_truncating();
	pub const GeneralAdminBodyId: BodyId = BodyId::Administration;
}

pub type IdentityAdminOrigin = EitherOfDiverse<
	EnsureRoot<AccountId>,
	EnsureXcm<IsVoiceOfBody<GovernanceLocation, GeneralAdminBodyId>>,
>;

impl pallet_identity::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type BasicDeposit = BasicDeposit;
	type ByteDeposit = ByteDeposit;
	type SubAccountDeposit = SubAccountDeposit;
	type MaxSubAccounts = ConstU32<100>;
	type IdentityInformation = IdentityInfo;
	type MaxRegistrars = ConstU32<20>;
	type Slashed = ToParentTreasury<RelayTreasuryAccount, LocationToAccountId, Runtime>;
	type ForceOrigin = EnsureRoot<Self::AccountId>;
	type RegistrarOrigin = IdentityAdminOrigin;
	type OffchainSignature = Signature;
	type SigningPublicKey = <Signature as Verify>::Signer;
	type UsernameAuthorityOrigin = IdentityAdminOrigin;
	type PendingUsernameExpiration = ConstU32<{ 7 * DAYS }>;
	type MaxSuffixLength = ConstU32<7>;
	type MaxUsernameLength = ConstU32<32>;
	type WeightInfo = weights::pallet_identity::WeightInfo<Runtime>;
}

/// The fields that we use to identify the owner of an account with. Each corresponds to a field
/// in the `IdentityInfo` struct.
#[bitflags]
#[repr(u64)]
#[derive(Clone, Copy, PartialEq, Eq, RuntimeDebug)]
pub enum IdentityField {
	Display,
	Legal,
	Web,
	Matrix,
	Email,
	PgpFingerprint,
	Image,
	Twitter,
	GitHub,
	Discord,
	Telegram,
	Bluesky,
	ForumPolkadot,
	Signal,
	LinkedIn,
	Facebook,
	Instagram,
	WhatsApp,
	Slack,
	IRC,
	Ed25519SSH,
}

/// Information concerning the identity of the controller of an account.
#[derive(
	CloneNoBound,
	Encode,
	Decode,
	EqNoBound,
	MaxEncodedLen,
	PartialEqNoBound,
	RuntimeDebugNoBound,
	TypeInfo,
)]
#[codec(mel_bound())]
pub struct IdentityInfo {
	/// A reasonable display name for the controller of the account. This should be whatever the  
	/// account is typically known as and should not be confusable with other entities, given  
	/// reasonable context.
	///
	/// Stored as UTF-8.
	pub display: Data,

	/// The full legal name in the local jurisdiction of the entity. This might be a bit
	/// long-winded.
	///
	/// Stored as UTF-8.
	pub legal: Data,

	/// A representative website held by the controller of the account.
	///
	/// NOTE: `https://` is automatically prepended.
	///
	/// Stored as UTF-8.
	pub web: Data,

	/// The Matrix (e.g. for Element) handle held by the controller of the account. Previously,
	/// this was called `riot`.
	///
	/// Stored as UTF-8.
	pub matrix: Data,

	/// The email address of the controller of the account.
	///
	/// Stored as UTF-8.
	pub email: Data,

	/// The PGP/GPG public key of the controller of the account.
	pub pgp_fingerprint: Option<[u8; 20]>,

	/// A graphic image representing the controller of the account. Should be a company,
	/// organization or project logo or a headshot in the case of a human.
	pub image: Data,

	/// The Twitter identity. The leading `@` character may be elided.
	pub twitter: Data,

	/// The GitHub username of the controller of the account.
	pub github: Data,

	/// The Discord username of the controller of the account.
	pub discord: Data,

	/// The Telegram username of the controller of the account
	/// (e.g. part inside <>, https://t.me/<username>).
	pub telegram: Data,

	/// The Bluesky/AT Protocol handle of the controller of the account
	/// (e.g., @alice.tld).
	pub bluesky: Data,

	/// The Polkadot Forum username of the controller of the account
	/// (e.g. part inside <>, forum.polkadot.network/u/<username>).
	pub forum_polkadot: Data,

	/// The Signal phone number of the controller of the account
	/// (e.g., alice12).
	pub signal: Data,

	/// The LinkedIn profile of the controller of the account
	/// (e.g. inside <>, https://linkedin.com/in/<username>).
	pub linkedin: Data,

	/// The Instagram username of the controller of the account
	/// (e.g. inside <>, https://instagram.com/<username>).
	pub instagram: Data,

	/// The Facebook profile of the controller of the account
	/// (e.g. inside <>, https://facebook.com/<username>).
	pub facebook: Data,

	/// The WhatsApp phone number of the controller of the account
	/// (e.g. inside <>, +1234567890).
	pub whatsapp: Data,

	/// The Slack username of the controller of the account, including the workspace domain
	/// (e.g., @username:workspace.slack.com).
	pub slack: Data,

	/// The IRC nickname of the controller of the account, including the server
	/// (e.g., nickname@irc.freenode.net).
	pub irc: Data,

	/// The Ed25519 SSH public key of the controller of the account.
	pub ed25519_ssh: Option<[u8; 64]>,
}

impl IdentityInformationProvider for IdentityInfo {
	type FieldsIdentifier = u64;

	fn has_identity(&self, fields: Self::FieldsIdentifier) -> bool {
		self.fields().bits() & fields == fields
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn create_identity_info() -> Self {
		let data = Data::Raw(vec![0; 32].try_into().unwrap());

		IdentityInfo {
			display: data.clone(),
			legal: data.clone(),
			web: data.clone(),
			matrix: data.clone(),
			email: data.clone(),
			pgp_fingerprint: Some([0; 20]),
			image: data.clone(),
			twitter: data.clone(),
			github: data.clone(),
			discord: data.clone(),
			telegram: data.clone(),
			bluesky: data.clone(),
			forum_polkadot: data.clone(),
			signal: data.clone(),
			linkedin: data.clone(),
			instagram: data.clone(),
			facebook: data.clone(),
			whatsapp: data.clone(),
			slack: data.clone(),
			irc: data,
			ed25519_ssh: Some([0; 64]),
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn all_fields() -> Self::FieldsIdentifier {
		use enumflags2::BitFlag;
		IdentityField::all().bits()
	}
}

impl IdentityInfo {
	pub(crate) fn fields(&self) -> BitFlags<IdentityField> {
		let mut res = <BitFlags<IdentityField>>::empty();
		if !self.display.is_none() {
			res.insert(IdentityField::Display);
		}
		if !self.legal.is_none() {
			res.insert(IdentityField::Legal);
		}
		if !self.web.is_none() {
			res.insert(IdentityField::Web);
		}
		if !self.matrix.is_none() {
			res.insert(IdentityField::Matrix);
		}
		if !self.email.is_none() {
			res.insert(IdentityField::Email);
		}
		if self.pgp_fingerprint.is_some() {
			res.insert(IdentityField::PgpFingerprint);
		}
		if !self.image.is_none() {
			res.insert(IdentityField::Image);
		}
		if !self.twitter.is_none() {
			res.insert(IdentityField::Twitter);
		}
		if !self.github.is_none() {
			res.insert(IdentityField::GitHub);
		}
		if !self.discord.is_none() {
			res.insert(IdentityField::Discord);
		}
		if !self.telegram.is_none() {
			res.insert(IdentityField::Telegram);
		}
		if !self.bluesky.is_none() {
			res.insert(IdentityField::Bluesky);
		}
		if !self.forum_polkadot.is_none() {
			res.insert(IdentityField::ForumPolkadot);
		}
		if !self.signal.is_none() {
			res.insert(IdentityField::Signal);
		}
		if !self.linkedin.is_none() {
			res.insert(IdentityField::LinkedIn);
		}
		if !self.instagram.is_none() {
			res.insert(IdentityField::Instagram);
		}
		if !self.facebook.is_none() {
			res.insert(IdentityField::Facebook);
		}
		if !self.whatsapp.is_none() {
			res.insert(IdentityField::WhatsApp);
		}
		if !self.slack.is_none() {
			res.insert(IdentityField::Slack);
		}
		if !self.irc.is_none() {
			res.insert(IdentityField::IRC);
		}
		if !self.ed25519_ssh.is_none() {
			res.insert(IdentityField::Ed25519SSH);
		}
		res
	}
}

/// A `Default` identity. This is given to users who get a username but have not set an identity.
impl Default for IdentityInfo {
	fn default() -> Self {
		IdentityInfo {
			display: Data::None,
			legal: Data::None,
			web: Data::None,
			matrix: Data::None,
			email: Data::None,
			pgp_fingerprint: None,
			image: Data::None,
			twitter: Data::None,
			github: Data::None,
			discord: Data::None,
			telegram: Data::None,
			bluesky: Data::None,
			forum_polkadot: Data::None,
			signal: Data::None,
			linkedin: Data::None,
			instagram: Data::None,
			facebook: Data::None,
			whatsapp: Data::None,
			slack: Data::None,
			irc: Data::None,
			ed25519_ssh: None,
		}
	}
}
