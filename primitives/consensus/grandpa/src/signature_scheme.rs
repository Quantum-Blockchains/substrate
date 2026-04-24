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

//! Abstraction layer for signature schemes used in GRANDPA consensus.
//!
//! Allows plugging in classical (sr25519) or post-quantum (ML-DSA-44) schemes
//! without changing the core consensus logic.

use codec::{Decode, Encode};
use sp_std::vec::Vec;

// ── PublicKey trait ──────────────────────────────────────────────────────────

/// A public key for a signature scheme.
///
/// Blanket-implemented for any type that is already `Encode + Decode + Clone + Eq`.
pub trait PublicKey: Encode + Decode + Clone + Eq + Send + Sync + 'static {
	/// Raw byte representation of this public key.
	fn to_bytes(&self) -> Vec<u8>;
}

impl PublicKey for sp_core::sr25519::Public {
	fn to_bytes(&self) -> Vec<u8> {
		self.0.to_vec()
	}
}

impl PublicKey for sp_core::ml_dsa::Public {
	fn to_bytes(&self) -> Vec<u8> {
		self.0.to_vec()
	}
}

// ── SignatureScheme trait ────────────────────────────────────────────────────

/// A stateless signature scheme: verify, and report key/signature sizes.
pub trait SignatureScheme: Send + Sync + 'static {
	/// The public key type for this scheme.
	type PublicKeyType: PublicKey;

	/// Verify `sig` over `msg` with `pk`.
	///
	/// `sig` is raw bytes (no length prefix).
	fn verify(msg: &[u8], sig: &[u8], pk: &Self::PublicKeyType) -> bool;

	/// Size in bytes of an encoded public key.
	fn public_key_size() -> usize;

	/// Size in bytes of an encoded signature.
	fn signature_size() -> usize;
}

// ── Sr25519Scheme ────────────────────────────────────────────────────────────

/// Schnorr/Ristretto25519 signature scheme (classical, 32-byte keys, 64-byte sigs).
///
/// Only available in std (client-side). Runtime verification goes through host
/// functions via `check_message_signature*`.
#[cfg(feature = "std")]
pub struct Sr25519Scheme;

#[cfg(feature = "std")]
impl SignatureScheme for Sr25519Scheme {
	type PublicKeyType = sp_core::sr25519::Public;

	fn verify(msg: &[u8], sig: &[u8], pk: &Self::PublicKeyType) -> bool {
		use sp_core::sr25519::Signature;
		use sp_core::Pair as _;

		let sig_arr: [u8; 64] = match sig.try_into() {
			Ok(a) => a,
			Err(_) => return false,
		};
		sp_core::sr25519::Pair::verify(&Signature(sig_arr), msg, pk)
	}

	fn public_key_size() -> usize {
		32
	}

	fn signature_size() -> usize {
		64
	}
}

// ── MlDsa44Scheme ────────────────────────────────────────────────────────────

/// ML-DSA-44 (FIPS 204) post-quantum signature scheme (1312-byte keys, 2420-byte sigs).
///
/// Only available in std (client-side). Runtime verification goes through host
/// functions via `check_message_signature*`.
#[cfg(feature = "std")]
pub struct MlDsa44Scheme;

#[cfg(feature = "std")]
impl SignatureScheme for MlDsa44Scheme {
	type PublicKeyType = sp_core::ml_dsa::Public;

	fn verify(msg: &[u8], sig: &[u8], pk: &Self::PublicKeyType) -> bool {
		use sp_core::ml_dsa::Signature;
		use sp_core::Pair as _;

		let sig_arr: [u8; sp_core::ml_dsa::SIGNATURE_LEN] = match sig.try_into() {
			Ok(a) => a,
			Err(_) => return false,
		};
		sp_core::ml_dsa::Pair::verify(&Signature(sig_arr), msg, pk)
	}

	fn public_key_size() -> usize {
		sp_core::ml_dsa::PUBLIC_KEY_LEN
	}

	fn signature_size() -> usize {
		sp_core::ml_dsa::SIGNATURE_LEN
	}
}

// ── Encode/Decode for Public keys ────────────────────────────────────────────
//
// sp_core::{sr25519,ml_dsa}::Public already derive Encode/Decode via codec,
// which writes the raw fixed-size array WITHOUT a length prefix (compact
// encoding of a fixed-size array in SCALE = just the bytes).  No extra wrapper
// needed here; the impls come for free from sp-core.
//
// If you need a length-prefixed encoding (e.g. in a heterogeneous context),
// use the helpers below.

/// Encode a public key as a SCALE byte-vec (with compact length prefix).
pub fn encode_public_key_prefixed<PK: PublicKey>(pk: &PK) -> Vec<u8> {
	pk.to_bytes().encode()
}

/// Decode a public key from a SCALE byte-vec (with compact length prefix).
pub fn decode_public_key_prefixed<PK: PublicKey>(input: &mut &[u8]) -> Result<PK, codec::Error> {
	let bytes = Vec::<u8>::decode(input)?;
	PK::decode(&mut bytes.as_slice())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::Pair as _;

	#[test]
	fn sr25519_scheme_sizes() {
		assert_eq!(Sr25519Scheme::public_key_size(), 32);
		assert_eq!(Sr25519Scheme::signature_size(), 64);
	}

	#[test]
	fn ml_dsa44_scheme_sizes() {
		assert_eq!(MlDsa44Scheme::public_key_size(), 1312);
		assert_eq!(MlDsa44Scheme::signature_size(), 2420);
	}

	#[test]
	fn sr25519_roundtrip() {
		let (pair, _) = sp_core::sr25519::Pair::generate();
		let msg = b"grandpa test message";
		let sig = pair.sign(msg);
		let pk = pair.public();
		assert!(Sr25519Scheme::verify(msg, sig.as_ref(), &pk));
		assert!(!Sr25519Scheme::verify(b"wrong", sig.as_ref(), &pk));
	}

	#[test]
	fn ml_dsa44_roundtrip() {
		let (pair, _) = sp_core::ml_dsa::Pair::generate();
		let msg = b"grandpa test message";
		let sig = pair.sign(msg);
		let pk = pair.public();
		assert!(MlDsa44Scheme::verify(msg, sig.as_ref(), &pk));
		assert!(!MlDsa44Scheme::verify(b"wrong", sig.as_ref(), &pk));
	}

	#[test]
	fn sr25519_wrong_sig_length_returns_false() {
		let (pair, _) = sp_core::sr25519::Pair::generate();
		let pk = pair.public();
		assert!(!Sr25519Scheme::verify(b"msg", &[0u8; 32], &pk));
	}

	#[test]
	fn ml_dsa44_wrong_sig_length_returns_false() {
		let (pair, _) = sp_core::ml_dsa::Pair::generate();
		let pk = pair.public();
		assert!(!MlDsa44Scheme::verify(b"msg", &[0u8; 64], &pk));
	}

	#[test]
	fn public_key_encode_decode_roundtrip_sr25519() {
		let (pair, _) = sp_core::sr25519::Pair::generate();
		let pk = pair.public();
		let encoded = encode_public_key_prefixed(&pk);
		let decoded: sp_core::sr25519::Public =
			decode_public_key_prefixed(&mut encoded.as_slice()).unwrap();
		assert_eq!(pk, decoded);
	}

	#[test]
	fn public_key_encode_decode_roundtrip_ml_dsa44() {
		let (pair, _) = sp_core::ml_dsa::Pair::generate();
		let pk = pair.public();
		let encoded = encode_public_key_prefixed(&pk);
		let decoded: sp_core::ml_dsa::Public =
			decode_public_key_prefixed(&mut encoded.as_slice()).unwrap();
		assert_eq!(pk, decoded);
	}
}
