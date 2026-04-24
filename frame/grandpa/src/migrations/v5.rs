// This file is part of Substrate.

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

//! Migration to v5: clear the GRANDPA authorities storage key.
//!
//! The authority key format changed from ed25519 (32-byte public key) to ML-DSA-44
//! (1312-byte public key). The old SCALE-encoded data cannot be decoded by the new
//! code, so the key must be cleared. Authorities will be repopulated by the next
//! session rotation using the new ML-DSA-44 keys.

use frame_support::{
	storage,
	traits::{Get, OnRuntimeUpgrade, StorageVersion},
	weights::Weight,
};
use sp_consensus_grandpa::GRANDPA_AUTHORITIES_KEY;

use crate::{Config, LOG_TARGET};

pub struct MigrateToMlDsa44<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> OnRuntimeUpgrade for MigrateToMlDsa44<T> {
	fn on_runtime_upgrade() -> Weight {
		let onchain = StorageVersion::get::<crate::Pallet<T>>();

		if onchain != 4 {
			log::warn!(
				target: LOG_TARGET,
				"MigrateToMlDsa44: skipping, expected storage version 4, found {:?}",
				onchain,
			);
			return T::DbWeight::get().reads(1)
		}

		log::info!(
			target: LOG_TARGET,
			"MigrateToMlDsa44: clearing GRANDPA_AUTHORITIES_KEY \
			 (ed25519 32-byte keys incompatible with ML-DSA-44 1312-byte keys). \
			 Authorities will be repopulated on next session rotation.",
		);

		storage::unhashed::kill(GRANDPA_AUTHORITIES_KEY);

		StorageVersion::new(5).put::<crate::Pallet<T>>();

		T::DbWeight::get().reads(1).saturating_add(T::DbWeight::get().writes(2))
	}
}
