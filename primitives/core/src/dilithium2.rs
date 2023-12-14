// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
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

//! Simple Dilithium2 API.

#[cfg(feature = "full_crypto")]
use core::convert::TryFrom;

#[cfg(feature = "std")]
use bip39::{Language, Mnemonic, MnemonicType};
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "std")]
use substrate_bip39::seed_from_entropy;

use sp_runtime_interface::pass_by::PassByInner;
use sp_std::ops::Deref;
#[cfg(feature = "full_crypto")]
use sp_std::vec::Vec;

use crate::crypto::ByteArray;
use crate::crypto::{
	CryptoType, CryptoTypeId, CryptoTypePublicPair, Derive, Public as TraitPublic, UncheckedFrom,
};
#[cfg(feature = "full_crypto")]
use crate::crypto::{DeriveJunction, Pair as TraitPair, SecretStringError};
#[cfg(feature = "std")]
use crate::crypto::Ss58Codec;
#[cfg(feature = "full_crypto")]
use crystals_dilithium::dilithium2 as dil2;

/// An identifier used to match public keys against dilithium2 keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"dth2");

/// A secret seed. It's not called a "secret key" because ring doesn't expose the secret keys
/// of the key pair (yeah, dumb); as such we're forced to remember the seed manually if we
/// will need it later (such as for HDKD).
#[cfg(feature = "full_crypto")]
type Seed = [u8; 32];

/// A public key.
#[cfg_attr(feature = "full_crypto", derive(Hash))]
#[derive(
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Clone,
	Copy,
	Encode,
	Decode,
	PassByInner,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct Public(pub [u8; 1312]);

/// A secret key.
#[cfg_attr(feature = "full_crypto", derive(Hash))]
#[derive(
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Clone,
	Copy,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct Secret(pub [u8; 32]);

/// A key pair.
#[cfg(feature = "full_crypto")]
#[derive(Copy, Clone)]
pub struct Pair {
	public: Public,
	secret: Secret,
}

impl AsRef<[u8; 1312]> for Public {
	fn as_ref(&self) -> &[u8; 1312] {
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
		if data.len() != Self::LEN {
			return Err(());
		}
		let mut r = [0u8; Self::LEN];
		r.copy_from_slice(data);
		Ok(Self::unchecked_from(r))
	}
}

impl From<Public> for [u8; 1312] {
	fn from(x: Public) -> Self {
		x.0
	}
}

impl From<Public> for [u8; 32] {
	fn from(x: Public) -> Self {
		x.0[..32].try_into().unwrap()
	}
}

#[cfg(feature = "full_crypto")]
impl From<Pair> for Public {
	fn from(x: Pair) -> Self {
		x.public()
	}
}

#[cfg(feature = "std")]
impl std::str::FromStr for Public {
	type Err = crate::crypto::PublicError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_ss58check(s)
	}
}

impl UncheckedFrom<[u8; 1312]> for Public {
	fn unchecked_from(x: [u8; 1312]) -> Self {
		Public::from_raw(x)
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for Public {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.to_ss58check())
	}
}

impl sp_std::fmt::Debug for Public {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		let s = self.to_ss58check();
		write!(f, "{} ({}...)", crate::hexdisplay::HexDisplay::from(&self.0.as_slice()), &s[0..8])
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

#[cfg(feature = "std")]
impl Serialize for Public {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
	{
		serializer.serialize_str(&self.to_ss58check())
	}
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for Public {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
	{
		Public::from_ss58check(&String::deserialize(deserializer)?)
			.map_err(|e| de::Error::custom(format!("{:?}", e)))
	}
}

/// A signature (a 512-bit value).
#[cfg_attr(feature = "full_crypto", derive(Hash))]
#[derive(
	Encode,
	Decode,
	PassByInner,
	MaxEncodedLen,
	TypeInfo,
	PartialEq,
	Eq
)]
pub struct Signature(pub [u8; 2420]);

impl TryFrom<&[u8]> for Signature {
	type Error = ();

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() == 2420 {
			let mut inner = [0u8; 2420];
			inner.copy_from_slice(data);
			Ok(Signature(inner))
		} else {
			Ok(Signature([0u8; 2420]))
		}
	}
}

#[cfg(feature = "std")]
impl Serialize for Signature {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
	{
		serializer.serialize_str(&hex::encode(self))
	}
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
	{
		let signature_hex = hex::decode(&String::deserialize(deserializer)?)
			.map_err(|e| de::Error::custom(format!("{:?}", e)))?;
		Signature::try_from(signature_hex.as_ref())
			.map_err(|e| de::Error::custom(format!("{:?}", e)))
	}
}

impl Clone for Signature {
	fn clone(&self) -> Self {
		let mut r = [0u8; 2420];
		r.copy_from_slice(&self.0[..]);
		Signature(r)
	}
}

impl From<Signature> for [u8; 2420] {
	fn from(v: Signature) -> [u8; 2420] {
		v.0
	}
}

impl AsRef<[u8; 2420]> for Signature {
	fn as_ref(&self) -> &[u8; 2420] {
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
		write!(f, "{}", crate::hexdisplay::HexDisplay::from(&self.0.as_slice()))
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

impl UncheckedFrom<[u8; 2420]> for Signature {
	fn unchecked_from(data: [u8; 2420]) -> Signature {
		Signature(data)
	}
}

#[cfg(feature = "full_crypto")]
impl Signature {
	/// A new instance from the given 64-byte `data`.
	///
	/// NOTE: No checking goes on to ensure this is a real signature. Only use it if
	/// you are certain that the array actually is a signature. GIGO!
	pub fn from_raw(data: [u8; 2420]) -> Signature {
		Signature(data)
	}

	/// A new instance from the given slice that should be 64 bytes long.
	///
	/// NOTE: No checking goes on to ensure this is a real signature. Only use it if
	/// you are certain that the array actually is a signature. GIGO!
	pub fn from_slice(data: &[u8]) -> Option<Self> {
		if data.len() != 2420 {
			return None;
		}
		let mut r = [0u8; 2420];
		r.copy_from_slice(data);
		Some(Signature(r))
	}
}

/// A localized signature also contains sender information.
#[cfg(feature = "std")]
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct LocalizedSignature {
	/// The signer of the signature.
	pub signer: Public,
	/// The signature itself.
	pub signature: Signature,
}

impl Public {
	/// A new instance from the given 32-byte `data`.
	///
	/// NOTE: No checking goes on to ensure this is a real public key. Only use it if
	/// you are certain that the array actually is a pubkey. GIGO!
	pub fn from_raw(data: [u8; 1312]) -> Self {
		Public(data)
	}

	/// A new instance from an H256.
	///
	/// NOTE: No checking goes on to ensure this is a real public key. Only use it if
	/// you are certain that the array actually is a pubkey. GIGO!
	//TODO Public key from H256
	// pub fn from_h256(x: H256) -> Self {
	// 	Public(x.into())
	// }

	/// Return a slice filled with raw data.
	pub fn as_array_ref(&self) -> &[u8; 1312] {
		self.as_ref()
	}
}

impl ByteArray for Public {
	const LEN: usize = 1312;
}

impl TraitPublic for Public {
	fn to_public_crypto_pair(&self) -> CryptoTypePublicPair {
		CryptoTypePublicPair(CRYPTO_ID, self.to_raw_vec())
	}
}

impl Derive for Public {}

impl From<Public> for CryptoTypePublicPair {
	fn from(key: Public) -> Self {
		(&key).into()
	}
}

impl From<&Public> for CryptoTypePublicPair {
	fn from(key: &Public) -> Self {
		CryptoTypePublicPair(CRYPTO_ID, key.to_raw_vec())
	}
}

/// Derive a single hard junction.
#[cfg(feature = "full_crypto")]
fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
	("DILITHIUM2HDKD", secret_seed, cc).using_encoded(sp_core_hashing::blake2_256)
}

/// An error when deriving a key.
#[cfg(feature = "full_crypto")]
pub enum DeriveError {
	/// A soft key was found in the path (and is unsupported).
	SoftKeyInPath,
}

#[cfg(feature = "full_crypto")]
impl TraitPair for Pair {
	type Public = Public;
	type Seed = Seed;
	type Signature = Signature;
	type DeriveError = DeriveError;
	#[cfg(feature = "std")]
	fn generate_with_phrase(_: Option<&str>) -> (Self, String, Self::Seed) {
		let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
		let phrase = mnemonic.phrase();
		let (pair, seed) = Self::from_phrase(phrase, None)
			.expect("All phrases generated by Mnemonic are valid; qed");
		(pair, phrase.to_owned(), seed)
	}

	#[cfg(feature = "std")]
	fn from_phrase(phrase: &str, password: Option<&str>) -> Result<(Self, Self::Seed), SecretStringError> {
		let big_seed = seed_from_entropy(
			Mnemonic::from_phrase(phrase, Language::English)
				.map_err(|_| SecretStringError::InvalidPhrase)?
				.entropy(),
			password.unwrap_or("")
		)
		.map_err(|_| SecretStringError::InvalidSeed)?;

		let mut seed = Seed::default();
		seed.copy_from_slice(&big_seed[0..32]);
		Self::from_seed_slice(&seed).map(|x| (x, seed))
	}

	fn derive<Iter: Iterator<Item=DeriveJunction>>(
		&self,
		path: Iter,
		_seed: Option<Seed>,
	) -> Result<(Self, Option<Seed>), Self::DeriveError> {
		// let acc = self.secret.0;
		// let mut seed = [0u8; 32];
		// match _seed {
		// 	Some(s) => seed.copy_from_slice(&s[0..32]),
		// 	None => seed.copy_from_slice(&acc[0..32])
		// };
		let mut acc = self.secret.0;
		for j in path {
			match j {
				DeriveJunction::Soft(_cc) => return Err(DeriveError::SoftKeyInPath),
				DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
			}
		}

		Ok((Self::from_seed(&acc), Some(acc)))
	}

	fn from_seed(seed: &Self::Seed) -> Self {
		Self::from_seed_slice(&seed[..]).expect("seed has valid length; qed")
	}

	fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError> {
		let pair: dil2::Keypair = dil2::Keypair::generate(Some(seed));
		// let secret = Secret(pair.secret.to_bytes());
		let public = Public(pair.public.to_bytes());

		let mut arr: [u8; 32] = [0; 32];
		arr.copy_from_slice(&seed[0..32]);

		let secret = Secret(arr);
		Ok(Pair {public, secret})
	}

	fn sign(&self, message: &[u8]) -> Self::Signature {

		let secret_key: dil2::SecretKey = dil2::Keypair::generate(Some(&self.secret.0)).secret;
		let r = secret_key.sign(message);
		Signature::from_raw(r)
	}

	fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, mess: M, pub_key: &Self::Public) -> bool {
		Self::verify_weak(&sig.0[..], mess.as_ref(), pub_key)
	}

	fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(sig_bytes: &[u8], message: M, pub_key_bytes: P) -> bool {
		let public_key: dil2::PublicKey = dil2::PublicKey::from_bytes(pub_key_bytes.as_ref());

		if sig_bytes.len() != 2420 {
			return false;
		}

		public_key.verify(message.as_ref(), sig_bytes)
	}

	fn public(&self) -> Self::Public {
		self.public
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		let mut vec_1 = self.secret.0.to_vec();
		let mut vec_2 = self.public.0.to_vec();
		vec_1.append(&mut vec_2);
		vec_1
	}
}

impl CryptoType for Public {
	#[cfg(feature = "full_crypto")]
	type Pair = Pair;
}

impl CryptoType for Signature {
	#[cfg(feature = "full_crypto")]
	type Pair = Pair;
}

#[cfg(feature = "full_crypto")]
impl CryptoType for Pair {
	type Pair = Pair;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_sign_and_verify() {
		let pair: Pair = TraitPair::from_seed(&[1u8; 32]);
		let message = [5u8; 10];

		let sig = pair.sign(&message);
		let verified = Pair::verify(&sig, message, &pair.public);

		assert!(verified);

		let incorrect_sig = Signature([2u8; 2420]);
		let verified = Pair::verify(&incorrect_sig, message, &pair.public);

		assert!(!verified);
	}
}
