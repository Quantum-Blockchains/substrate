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

//! ML-DSA-44 (FIPS 204) post-quantum signature scheme.
//!
//! Key sizes:
//!   Public key:  1312 bytes
//!   Private key: 2528 bytes (expanded form)
//!   Signature:   2420 bytes
//!   Seed:          32 bytes

#[cfg(feature = "full_crypto")]
use sp_std::vec::Vec;

use crate::crypto::{
	ByteArray, CryptoType, CryptoTypeId, Derive, FromEntropy, Public as TraitPublic, UncheckedFrom,
};
#[cfg(feature = "full_crypto")]
use crate::crypto::{DeriveError, DeriveJunction, Pair as TraitPair, SecretStringError};

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use crate::crypto::Ss58Codec;
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sp_runtime_interface::pass_by::PassByInner;
use sp_std::ops::Deref;
#[cfg(feature = "full_crypto")]
use core::convert::TryFrom;

/// An identifier used to match public keys against ML-DSA-44 keys.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"mdsa");

/// ML-DSA-44 public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 1312;
/// ML-DSA-44 signature length in bytes.
pub const SIGNATURE_LEN: usize = 2420;
/// ML-DSA-44 private key (expanded form) length in bytes.
pub const SECRET_KEY_LEN: usize = 2560;
/// Seed length for deterministic key generation (ML-DSA xi parameter).
pub const SEED_LEN: usize = 32;

/// An ML-DSA-44 public key (1312 bytes).
#[cfg_attr(feature = "full_crypto", derive(Hash))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, PassByInner, MaxEncodedLen, TypeInfo)]
pub struct Public(pub [u8; PUBLIC_KEY_LEN]);

impl AsRef<[u8; PUBLIC_KEY_LEN]> for Public {
	fn as_ref(&self) -> &[u8; PUBLIC_KEY_LEN] {
		&self.0
	}
}

impl AsRef<[u8]> for Public {
	fn as_ref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl AsMut<[u8]> for Public {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0[..]
	}
}

impl Deref for Public {
	type Target = [u8];
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl TryFrom<&[u8]> for Public {
	type Error = ();
	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() != PUBLIC_KEY_LEN {
			return Err(())
		}
		let mut r = [0u8; PUBLIC_KEY_LEN];
		r.copy_from_slice(data);
		Ok(Public(r))
	}
}

impl ByteArray for Public {
	const LEN: usize = PUBLIC_KEY_LEN;
}

impl TraitPublic for Public {}

impl Derive for Public {}

impl UncheckedFrom<[u8; PUBLIC_KEY_LEN]> for Public {
	fn unchecked_from(data: [u8; PUBLIC_KEY_LEN]) -> Self {
		Public(data)
	}
}

impl FromEntropy for Public {
	fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
		let mut result = Self([0u8; PUBLIC_KEY_LEN]);
		input.read(&mut result.0[..])?;
		Ok(result)
	}
}

impl sp_std::fmt::Debug for Public {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(f, "{}", crate::hexdisplay::HexDisplay::from(&&self.0[..8]))
	}
	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

#[cfg(feature = "std")]
impl std::str::FromStr for Public {
	type Err = crate::crypto::PublicError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_ss58check(s)
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for Public {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.to_ss58check())
	}
}

#[cfg(feature = "serde")]
impl Serialize for Public {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_ss58check())
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Public {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Public::from_ss58check(&String::deserialize(deserializer)?)
			.map_err(|e| de::Error::custom(format!("{:?}", e)))
	}
}

impl CryptoType for Public {
	#[cfg(feature = "full_crypto")]
	type Pair = Pair;
}

/// An ML-DSA-44 signature (2420 bytes).
#[cfg_attr(feature = "full_crypto", derive(Hash))]
#[derive(Encode, Decode, MaxEncodedLen, PassByInner, TypeInfo, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

impl Clone for Signature {
	fn clone(&self) -> Self {
		let mut r = [0u8; SIGNATURE_LEN];
		r.copy_from_slice(&self.0[..]);
		Signature(r)
	}
}

impl TryFrom<&[u8]> for Signature {
	type Error = ();
	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() != SIGNATURE_LEN {
			return Err(())
		}
		let mut inner = [0u8; SIGNATURE_LEN];
		inner.copy_from_slice(data);
		Ok(Signature(inner))
	}
}

impl AsRef<[u8; SIGNATURE_LEN]> for Signature {
	fn as_ref(&self) -> &[u8; SIGNATURE_LEN] {
		&self.0
	}
}

impl AsRef<[u8]> for Signature {
	fn as_ref(&self) -> &[u8] {
		&self.0[..]
	}
}

impl AsMut<[u8]> for Signature {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0[..]
	}
}

impl sp_std::fmt::Debug for Signature {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(f, "MlDsa44Sig({:?}...)", &self.0[..8])
	}
	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

impl UncheckedFrom<[u8; SIGNATURE_LEN]> for Signature {
	fn unchecked_from(data: [u8; SIGNATURE_LEN]) -> Signature {
		Signature(data)
	}
}

#[cfg(feature = "serde")]
impl Serialize for Signature {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&array_bytes::bytes2hex("", &self.0[..]))
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let sig_hex = array_bytes::hex2bytes(&String::deserialize(deserializer)?)
			.map_err(|e| de::Error::custom(format!("{:?}", e)))?;
		Signature::try_from(sig_hex.as_ref())
			.map_err(|e| de::Error::custom(format!("{:?}", e)))
	}
}

impl CryptoType for Signature {
	#[cfg(feature = "full_crypto")]
	type Pair = Pair;
}

/// An ML-DSA-44 key pair.
///
/// The seed (32 bytes) is stored so the pair can be re-derived from a URI/phrase.
/// Actual signing and verification use the expanded 2528-byte private key derived
/// deterministically from the seed via a seeded PRNG (ChaCha20).
#[cfg(feature = "full_crypto")]
#[derive(Clone)]
pub struct Pair {
	seed: [u8; SEED_LEN],
	pk: [u8; PUBLIC_KEY_LEN],
	sk: [u8; SECRET_KEY_LEN],
}

#[cfg(feature = "full_crypto")]
fn derive_hard_junction(secret_seed: &[u8; SEED_LEN], cc: &[u8; 32]) -> [u8; SEED_LEN] {
	("MlDsa44HDKD", secret_seed, cc).using_encoded(sp_core_hashing::blake2_256)
}

#[cfg(feature = "full_crypto")]
fn keygen_from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
	use fips204::ml_dsa_44;
	use fips204::traits::SerDes;
	use rand_chacha::ChaCha20Rng;
	use rand_chacha::rand_core::SeedableRng;

	let mut rng = ChaCha20Rng::from_seed(*seed);
	let (pk_obj, sk_obj) =
		ml_dsa_44::try_keygen_with_rng(&mut rng).expect("ML-DSA-44 key generation failed");

	let pk = pk_obj.into_bytes();
	let sk = sk_obj.into_bytes();
	(pk, sk)
}

#[cfg(feature = "full_crypto")]
impl TraitPair for Pair {
	type Public = Public;
	type Seed = [u8; SEED_LEN];
	type Signature = Signature;

	fn from_seed_slice(seed_slice: &[u8]) -> Result<Pair, SecretStringError> {
		if seed_slice.len() != SEED_LEN {
			return Err(SecretStringError::InvalidSeedLength)
		}
		let mut seed = [0u8; SEED_LEN];
		seed.copy_from_slice(seed_slice);
		let (pk, sk) = keygen_from_seed(&seed);
		Ok(Pair { seed, pk, sk })
	}

	fn derive<Iter: Iterator<Item = DeriveJunction>>(
		&self,
		path: Iter,
		_seed: Option<[u8; SEED_LEN]>,
	) -> Result<(Pair, Option<[u8; SEED_LEN]>), DeriveError> {
		let mut acc = self.seed;
		for j in path {
			match j {
				DeriveJunction::Soft(_cc) => return Err(DeriveError::SoftKeyInPath),
				DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
			}
		}
		Ok((Self::from_seed(&acc), Some(acc)))
	}

	fn public(&self) -> Public {
		Public(self.pk)
	}

	fn sign(&self, message: &[u8]) -> Signature {
		use fips204::ml_dsa_44;
		use fips204::traits::{SerDes, Signer};
		use rand_chacha::ChaCha20Rng;
		use rand_chacha::rand_core::SeedableRng;

		let sk = ml_dsa_44::PrivateKey::try_from_bytes(self.sk)
			.expect("stored secret key is always valid");
		// Deterministic RNG seeded from key material + message for reproducible signatures.
		let rng_seed = sp_core_hashing::blake2_256(&[&self.seed[..], message].concat());
		let mut rng = ChaCha20Rng::from_seed(rng_seed);
		let sig_bytes = sk
			.try_sign_with_rng(&mut rng, message, b"")
			.expect("ML-DSA-44 signing failed");
		Signature(sig_bytes)
	}

	fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, public: &Public) -> bool {
		use fips204::ml_dsa_44;
		use fips204::traits::{SerDes, Verifier};

		let pk = match ml_dsa_44::PublicKey::try_from_bytes(public.0) {
			Ok(pk) => pk,
			Err(_) => return false,
		};
		pk.verify(message.as_ref(), &sig.0, b"")
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.seed.to_vec()
	}
}

#[cfg(feature = "full_crypto")]
impl CryptoType for Pair {
	type Pair = Pair;
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::crypto::DEV_PHRASE;

	#[test]
	fn generated_pair_should_work() {
		let (pair, _) = Pair::generate();
		let public = pair.public();
		let message = b"ML-DSA-44 test message";
		let signature = pair.sign(&message[..]);
		assert!(Pair::verify(&signature, &message[..], &public));
		assert!(!Pair::verify(&signature, b"Wrong message", &public));
	}

	#[test]
	fn seeded_pair_should_be_deterministic() {
		let seed = b"12345678901234567890123456789012";
		let pair1 = Pair::from_seed(seed);
		let pair2 = Pair::from_seed(seed);
		assert_eq!(pair1.public(), pair2.public());
	}

	#[test]
	fn default_phrase_should_be_used() {
		assert_eq!(
			Pair::from_string("//Alice///password", None).unwrap().public(),
			Pair::from_string(&format!("{}//Alice", DEV_PHRASE), Some("password"))
				.unwrap()
				.public(),
		);
	}
}
