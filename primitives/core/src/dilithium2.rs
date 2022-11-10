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

use crate::{
	crypto::ByteArray,
};
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use crate::crypto::Ss58Codec;
use crate::crypto::{
	CryptoType, CryptoTypeId, CryptoTypePublicPair, Derive, Public as TraitPublic, UncheckedFrom,
};
#[cfg(feature = "full_crypto")]
use crate::crypto::{DeriveJunction, Pair as TraitPair, SecretStringError};
#[cfg(feature = "std")]
use bip39::{Language, Mnemonic, MnemonicType};
#[cfg(feature = "full_crypto")]
use core::convert::TryFrom;
#[cfg(feature = "std")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sp_std::ops::Deref;
#[cfg(feature = "std")]
use substrate_bip39::seed_from_entropy;

#[cfg(feature = "full_crypto")]
use sp_std::vec::Vec;

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
	// PassByInner,
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
	// PassByInner,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct Secret(pub [u8; 2528]);

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
			return Err(())
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
	MaxEncodedLen,
	// PassByInner,
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
			Err(())
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
			return None
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
	fn from_phrase(_: &str, _: Option<&str>) -> Result<(Self, Self::Seed), SecretStringError> {
		let mut seed = Seed::default();
		Self::from_seed_slice(&seed).map(|x| (x, seed))
	}

	fn derive<Iter: Iterator<Item = DeriveJunction>>(
		&self,
		_: Iter,
		_: Option<Seed>,
	) -> Result<(Self, Option<Seed>), Self::DeriveError> {
		let seed = Seed::default();
		Ok((Self::from_seed(&seed), Some(seed)))
	}
	fn from_seed(_: &Self::Seed) -> Self {
		let public_bytes: Vec<u8> = (0..1312).map(|_| { rand::random::<u8>() }).collect();
		let public = Public(<[u8; 1312]>::try_from(public_bytes.as_slice()).unwrap());
		let secret_bytes: Vec<u8> = (0..2528).map(|_| { rand::random::<u8>() }).collect();
		let secret = Secret(<[u8; 2528]>::try_from(secret_bytes.as_slice()).unwrap());

		Pair { public, secret }
	}

	fn from_seed_slice(_: &[u8]) -> Result<Self, SecretStringError> {
		Ok(Self::from_seed(&Seed::default()))
	}
	fn sign(&self, _: &[u8]) -> Self::Signature {
		let sig_bytes: Vec<u8> = (0..2420).map(|_| { rand::random::<u8>() }).collect();
		Signature(<[u8; 2420]>::try_from(sig_bytes.as_slice()).unwrap())
	}
	fn verify<M: AsRef<[u8]>>(_: &Self::Signature, _: M, _: &Self::Public) -> bool {
		true
	}
	fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(_: &[u8], _: M, _: P) -> bool {
		true
	}
	fn public(&self) -> Self::Public {
		self.public
	}
	fn to_raw_vec(&self) -> Vec<u8> {
		Vec::new()
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
