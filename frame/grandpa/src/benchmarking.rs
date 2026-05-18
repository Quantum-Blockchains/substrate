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

//! Benchmarks for the GRANDPA pallet.

use super::{Pallet as Grandpa, *};
use ::grandpa as finality_grandpa;
use frame_benchmarking::v1::benchmarks;
use frame_system::RawOrigin;
use sp_core::{mldsa44, H256, Pair as _};

fn mldsa44_pair_from_seed(seed: [u8; 32]) -> mldsa44::Pair {
	mldsa44::Pair::from_seed(&seed)
}

fn generate_benchmark_equivocation_proof(
	set_id: sp_consensus_grandpa::SetId,
	vote1: (sp_consensus_grandpa::RoundNumber, H256, u64, &mldsa44::Pair),
	vote2: (sp_consensus_grandpa::RoundNumber, H256, u64, &mldsa44::Pair),
) -> sp_consensus_grandpa::EquivocationProof<H256, u64> {
	let signed_prevote = |round, hash, number, pair: &mldsa44::Pair| {
		let prevote = finality_grandpa::Prevote { target_hash: hash, target_number: number };
		let prevote_msg = finality_grandpa::Message::Prevote(prevote.clone());
		let payload = sp_consensus_grandpa::localized_payload(round, set_id, &prevote_msg);
		let signed = pair.sign(&payload).into();
		(prevote, signed)
	};

	let (prevote1, signed1) = signed_prevote(vote1.0, vote1.1, vote1.2, vote1.3);
	let (prevote2, signed2) = signed_prevote(vote2.0, vote2.1, vote2.2, vote2.3);

	sp_consensus_grandpa::EquivocationProof::new(
		set_id,
		sp_consensus_grandpa::Equivocation::Prevote(finality_grandpa::Equivocation {
			round_number: vote1.0,
			identity: vote1.3.public().into(),
			first: (prevote1, signed1),
			second: (prevote2, signed2),
		}),
	)
}

benchmarks! {
	check_equivocation_proof {
		let x in 0 .. 1;

		let alice_pair = mldsa44_pair_from_seed([1u8; 32]);
		let set_id = 1u64;

		let equivocation_proof1 = generate_benchmark_equivocation_proof(
			set_id,
			(1, H256::repeat_byte(1), 10, &alice_pair),
			(1, H256::repeat_byte(2), 10, &alice_pair),
		);

		let equivocation_proof2 = equivocation_proof1.clone();
	}: {
		sp_consensus_grandpa::check_equivocation_proof(equivocation_proof1);
	} verify {
		assert!(sp_consensus_grandpa::check_equivocation_proof(equivocation_proof2));
	}

	note_stalled {
		let delay = 1000u32.into();
		let best_finalized_block_number = 1u32.into();

	}: _(RawOrigin::Root, delay, best_finalized_block_number)
	verify {
		assert!(Grandpa::<T>::stalled().is_some());
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::mock::new_test_ext(vec![(1, 1), (2, 1), (3, 1)]),
		crate::mock::Test,
	);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::*;

	#[test]
	fn test_generate_equivocation_report_blob() {
		let authorities = crate::tests::test_authorities();

		let equivocation_authority_index = 0;
		let equivocation_key = &authorities[equivocation_authority_index].0;
		let equivocation_keyring = extract_keyring(equivocation_key);

		new_test_ext_raw_authorities(authorities).execute_with(|| {
			start_era(1);

			// generate an equivocation proof, with two votes in the same round for
			// different block hashes signed by the same key
			let equivocation_proof = generate_equivocation_proof(
				1,
				(1, H256::random(), 10, &equivocation_keyring),
				(1, H256::random(), 10, &equivocation_keyring),
			);

			println!("equivocation_proof: {:?}", equivocation_proof);
			println!("equivocation_proof.encode(): {:?}", equivocation_proof.encode());
		});
	}
}
