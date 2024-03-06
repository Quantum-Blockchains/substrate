// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! implementation of the `verify` subcommand

use crate::{error, params::MessageParams, utils, with_crypto_scheme, CryptoSchemeFlag};
use clap::Parser;
use sp_core::crypto::{ByteArray, Ss58Codec};
use std::io::BufRead;

/// The `verify` command
#[derive(Debug, Clone, Parser)]
#[command(
	name = "verify",
	about = "Verify a signature for a message, provided on STDIN, with a given (public or secret) key"
)]
pub struct VerifyCmd {
	/// Signature, hex-encoded.
	sig: String,

	/// The public or secret key URI.
	/// If the value is a file, the file content is used as URI.
	/// If not given, you will be prompted for the URI.
	uri: Option<String>,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub message_params: MessageParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub crypto_scheme: CryptoSchemeFlag,
}

impl VerifyCmd {
	/// Run the command
	pub fn run(&self) -> error::Result<()> {
		self.verify(|| std::io::stdin().lock())
	}

	/// Verify a signature for a message.
	///
	/// The message can either be provided as immediate argument via CLI or otherwise read from the
	/// reader created by `create_reader`. The reader will only be created in case that the message
	/// is not passed as immediate.
	pub(crate) fn verify<F, R>(&self, create_reader: F) -> error::Result<()>
	where
		R: BufRead,
		F: FnOnce() -> R,
	{
		let message = self.message_params.message_from(create_reader)?;
		let sig_data = array_bytes::hex2bytes(&self.sig)?;
		let uri = utils::read_uri(self.uri.as_ref())?;
		let uri = if let Some(uri) = uri.strip_prefix("0x") { uri } else { &uri };

		with_crypto_scheme!(self.crypto_scheme.scheme, verify(sig_data, message, uri))
	}
}

fn verify<Pair>(sig_data: Vec<u8>, message: Vec<u8>, uri: &str) -> error::Result<()>
where
	Pair: sp_core::Pair,
	Pair::Signature: for<'a> TryFrom<&'a [u8]>,
{
	let signature =
		Pair::Signature::try_from(&sig_data).map_err(|_| error::Error::SignatureFormatInvalid)?;

	let pubkey = if let Ok(pubkey_vec) = array_bytes::hex2bytes(uri) {
		Pair::Public::from_slice(pubkey_vec.as_slice())
			.map_err(|_| error::Error::KeyFormatInvalid)?
	} else {
		Pair::Public::from_string(uri)?
	};

	if Pair::verify(&signature, &message, &pubkey) {
		println!("Signature verifies correctly.");
	} else {
		return Err(error::Error::SignatureInvalid)
	}

	Ok(())
}

#[cfg(test)]
mod test {
	use super::*;

	const ALICE: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
	const SIG1: &str = "0x4eb25a2285a82374888880af0024eb30c3a21ce086eae3862888d345af607f0ad6fb081312f11730932564f24a9f8ebcee2d46861413ae61307eca58db2c3e81";
	const SIG2: &str = "0x026342225155056ea797118c1c8c8b3cc002aa2020c36f4217fa3c302783a572ad3dcd38c231cbaf86cadb93984d329c963ceac0685cc1ee4c1ed50fa443a68f";

	// Verify work with `--message` argument.
	#[test]
	fn verify_immediate() {
		let cmd = VerifyCmd::parse_from(&["verify", SIG1, ALICE, "--message", "test message"]);
		assert!(cmd.run().is_ok(), "Alice' signature should verify");
	}

	// Verify work without `--message` argument.
	#[test]
	fn verify_stdin() {
		let cmd = VerifyCmd::parse_from(&["verify", SIG1, ALICE]);
		let message = "test message";
		assert!(cmd.verify(|| message.as_bytes()).is_ok(), "Alice' signature should verify");
	}

	// Verify work with `--message` argument for hex message.
	#[test]
	fn verify_immediate_hex() {
		let cmd = VerifyCmd::parse_from(&["verify", SIG2, ALICE, "--message", "0xaabbcc", "--hex"]);
		assert!(cmd.run().is_ok(), "Alice' signature should verify");
	}

	// Verify work without `--message` argument for hex message.
	#[test]
	fn verify_stdin_hex() {
		let cmd = VerifyCmd::parse_from(&["verify", SIG2, ALICE, "--hex"]);
		assert!(cmd.verify(|| "0xaabbcc".as_bytes()).is_ok());
		assert!(cmd.verify(|| "aabbcc".as_bytes()).is_ok());
		assert!(cmd.verify(|| "0xaABBcC".as_bytes()).is_ok());
	}

	#[test]
	fn verify_with_dilithium2_scheme() {
		let pubkey = "0x2d9af53a848af6f5ff1d729b71f25e5431d8442c0cc23a07d03386e90132c62857e58e33461c0fab969035cde865b54ac851f7a25c81afde2d9af53a848af6f5ff1d729b71f25e5431d8442c0cc23a07d03386e90132c62857e58e33461c0fab969035cde865b54ac851f7a25c81afde2d9af53a848af6f5ff1d729b71f25e5431d8442c0cc23a07d03386e90132c62857e58e33461c0fab969035cde865b54ac851f7a25c81afde2d9af53a848af6f5ff1d729b71f25e5431d8442c0cc23a07d03386e90132c62857e58e33461c0fab969035cde865b54ac851f7a25c81afdec851f7a25c81afde2d9af53a848af6f5ff1d729b71f25e5431d8442c0cc23a07d03386e90132c62857e58e33461c0fab969035cde865b54ac851f7a25c81afde2d9af53a848af6f5ff1d729b71f25e5431d8442c0cc23a07d03386e90132c62857e58e33461c0fab969035cde865b54ac851f7a25c81afde108add7894fdbcf94a013f164afdbe32a2ae68192413229523ef4ae9d7fa761c9cf5824faeeff4241a372b520113e15243d2673955f52c0bfd300069379cd3f47be485bb361d7e1ae4cac0929cc38ecd7299589f48d3f05124c95208659a88bef62b7eb8b2f1de8d15ee07665fa5b7134c38b4f9be0a9228bd9cc96fbd1cf1f2271396d4634fd67668d868447a2e73952ed2c82bf2f79a34ada57485e652d88c2ee4b1bb3413d4fb93adcee7ce2321baf6a94818badc617016ff127b069d4a3b3a1909a014e3e436ac13de897613e9eebf7d0ae98076c3bbc40ee6860528caf099fa628f45d09a852569457a586f5d1f5893059cef471c25f79203718dc5a491f785fcee205643731f3c10d4272672c12f2f187e37fc236c457bc4d81a380f277eb7e866737c3f5057df66763c7fed9fd690030406f6554a10b2b902728146cc814b64200b05dd836271310c95e20f8280b0736c2bf7e70b6d4941369342b110589372575a6e8c7fef5686312bf470b772991efa48b7d593e0e5ca2f1bbab99091d9ea29d7925eee039e922fddf9817572e9277646706bb9f183820293992041e77d87c8171087ba35077807dcccd2f82a526777804641ae93385de9d2dfe46b998cea1966e9768dfba77ce0ebb116e374796fe22c3977d5168434336d99b2c074434456f22277199a32840b009faa9dca2aa178c95a05a2061cf67ad5fbf4c3a65d107d2c9230179fcc0ed0564461bf087514c303348f8e9a51a2ed2477e0a0a13ebf5f51ba600ef883aab1d0283c51f8e95fd1a7291e67fd22a11f8753adbe1c064d3e525986e65b1220d146051b76d8fde188713579b4c3559e07f47f0da06ea05d7a6a4d12716985b6df10efd6506c3f63ce01c25995dee6d86b83ce9b0bd2bb2d7b6915a2b7e0d587e5e14484f015ebfcc13e0affc9a29110629e0c07a3de3235225da2ca4b6ce759b66ce26a3d9130a1d6a7c39d265f9e3ce13470ac80136fa9da0682fdf5352f3d3c1fdc3c45195b7d916ff5297661843a8d5b5655e0a20f4198c15ed7cd46531c578d5e09f8e82f193a50d5ce800c396ed2e4449bcbbac0959cb6d572ea03cb15eab37f6d0424e436718f9e3cda932962639a1006c6c45614e00c5200553f4a9702835523a69f156117b01e9b282fd06361bbdcbd6561fcb639dc0adcb7450a5f83caa4e20498ccc777706b815096dec7f14323e2c044c35fe452aae09b70410c2d483432da73d688de90034830ea2f6432039df8d794b3f78ed9b7389044885a3260042e2bf4383dfc3833d76abb6a2e3ca7f7b7cf86ba8eae2aa0b88d2f21d1bed7c36328cbf0e1a0008b4cb4e57ce336006c2565bf4d4d34837bbee7";
		let signature = "0xec6ef67092f6eabd6306944fefa5333addfc539d2cfae70f76f8322e7c942473f9a2734c85d9e5324214055bd095dd68e7815f34a12e2430c47d193808aecb80ecd53b98c11718ca29d48b5d49473f1d4cf13c0e08b344abdead7eed58c957a075d2a774f81ca1c7fc4fe189325f23fa1cfb101613655563f2f8c9dade6e01a172e239092b9738c22431a71e4890791a9048c34ab10e539d96c2a26c233259ea85b6e28c4f79f70ccef00ae6880739750fc90875f1fb8a43dd42a443e60724d2ef35481d875fb6bb1d221c65c423334cd30d4839b80a69ff63c9ebd3430c75c4584dbe3baedbb3f31dfab24981b9f74b3ae4362fdf06db7bc12e7b0d1a9fc655e3fc51156f869630d126ee816c343362a35b34ce12a5c1d8915ce64f365d23604a517e5f6b909c3c1e288168f96330f4a234ab95c407966f7be16674a5c821ae4da1f7d78b0979cd6188f4db7f55af2c3476c36a427976c1222c93bf04825b14fcf0bf0640c178f498d5fb0b7209885559b24504766f9cfa9d0787069025b20157b24db480186009b0a8b9b8909ee00f6d4d5d4d471cc4498380b0c0e942db3ab74ff0d31acf439233a550362d3cdf60791bb94de4de234cfa95cc024cff8183cd1ebb224245ba89fa5584e75323415cf2b486e858e2d4768fee272fc41a6edb1c889108770169c552bc557b2b2191633a48da923dd11c42dfd60e935b370539258b51a4c7c9a5efde9bdf778505e6b4c42dadd8e5e272cd43a384b6197349f9f0749aceed2ca1ee9061715208155da4589fb378140355acf7ffc07f6b44570a90062833885f0d8d06ed345f784f26a36e63cbd14af20ddf1cee0154089012e242937a994785deee06e64c008639fe36bd62b22404940e1f738cbeb896db4e081b98adf830fd64e60005158911efcaa9d34d3170572b6d890d7a1196e1ddfc54f2b199ce771b10057e03577622be276041b8a96f9cc650c9d8c1fad28bc3a9e2eb8ca3fad1210044e2cd66a1a50bc97c8fd4a0c0de2290637833ec75d1ed8ca125cd192990792fcd1d470e21d80afa339b1e784aa30808a655ac96bec70e31f1e34a1f0beb290ba9c16b3a61ac3b1db2eb308b935b62734ff73937b9451b699689578808077d32b1869769998f0b3a777ff1ec7c639c93a928d77138462c25ed6ab089db74e54938dc219afbd6b5c3fb8db83d349908b64400153e16a109520e02abdeab5bedd0c9f2ae7f29bad12abe0164daf01314c922befca2fda4a348ee07923aed57d13d5151f862c430e20f5acb793308167a992890d445804f684327c726608bb74a0670fa1de024a62c4406e39bd9cc65b73519da6caf04f7d344c156f7e2fd00ac8a79d7b0adcce35e5e667259e5609a40b032515b0e637671a5ce62228f7ef9a02076e18bb66fc5e904cc68d1ec9dba729a013f7c957b43057a23b101580302077b6af3c757cf7f0abac9ca0320a70f04e72e2c27261af225ebfeb2bae384a2b964d7074cceaefc474a978f656d1dec108233a36ca34dda7bfbfbce4c39bb58f4501ee066d162d6757287862af64634343e33e4fe14f19e07ab5268d315ab1130f9b98b3c93064e23e1055f36351dc6aef7940b828ef1ca2b6ba6457d476123a77ca8332c352f2109ea27d550fdb662742bc72292ead2efd7e51bc468bb2a3e3ef89a5c2b5b2d58753a3eaa4415345669f7948ba9f99b798506d6789f9e473dd8326300c09499e2dc6a2bc90f668188552604d3e55e37a4a1fd0706295780cbd37ea749162c92cd0161835824579f29492a1147c870a23b9eadddca1e06375f2430065020062db4dbe9baa02b637f540f2dc5c3e2e7b6d98fdefaea55c0dce140c86f64b7bfb301f9a64aab8f1492bd560027bc9585b866d5bc0ff6579abd10e08c77c83a8cd190cd76f534fbe3688d0442a93f7e4289b756e786257fdb902babf6f784468493a2c6fa69cb184305f286e38bc0c9921af27b017d9d3a766ada5f054626699a865dbcc199fc260f0e08e0d40eef15958f2705bd4e99c4483e634eaa110021e6cdaa534bda5873a0185979aab52bf3622fa0b4bc05b415b5ba5ca92e1363ecd9b0426a43ea395ee392207902045c34b26ee545298f1c3406ae8ccc20b885a446cf2c0cab74e1c895b616794a1de366afa4e548c7e047dc336c65f44f8b36a8ad3719b206841aede430d014c7deebdba729c30f3f7b363fd5511d59a56d5f962bb763c541fc9193939d77e48a884206585858361d76a6c62efe535bf04c91629d958ed4297106180d3092a001d1edc13d3c70e0790dbb09f25c620da3845c91d60e0ea904a6c3339e6fa94eb262ed9f104be837660b6a22e050233f55010bbfa939f4360a6527d48ea43bd7724e2d3554323dda14bef0455bc5f0646fe4b2d0d25c0cde7abddfef2daf8baaf149668c801807e961c100947b8839dfac65827394c31cbb64ec55bc620d953836aba1ac23c8b1c3c9a9e46e90a22af8577f3c5bab85ad03f385987fc3eac26f65fcd4ba5563f0d8c20df2cbfa257a13daa9ff3131b6e3a8fc693a01332b65e45a8031b58081aa451e12a7ad5f3cfde22a387571349768197343cf49a56bf5c80c5bdf57e1062a25e3c8ac05794cfd2f2be6397c1ef2622e4df28ac64bb45603c1340b10658387fbef7517807fe0493eb3ebcf6ee2b716a6b3c225e3ca351c7e686e912911e72f3ddd0bad712554266efc782cd759b3137b4954a269463495955a7eeb1031aceb573253b667cd1d26b3cf6cae8997a02b23938a4447b53436f40594eca649922311c228eb730660c23ca96105fa7c64345efc2f1903f666b2c412a57fa691ec04f9691cfadae0ec8e13bfdbf0e4edc07d3547abe6d5123b6675be5e4cdc7a81adcad9560ecfbcae4d756128ca8e2f5df3ef3c5668d791a50072a8d811535128036654c7acbf19e74dfd59973fb1e7024c23a67e6030726f2de3ad85232eb9c1df4ae1079957daa885adea1b187e9da6f45e084edc17a6a354ec0b0f409fd276895a8d9fa6d8445989be82fb896f52e7b7f3794ddce454a9d4e5e7b3009499df6b74b29860ad587aca772f9629fda61f92fc53ee18870d24c73d3ea6348c3bf67e9be2c88a0595d297774566006d720b14e7a37f2a716bc7a797d339b544c7d28e657e8470a82db17a864cbd0e948bfaf12f241673743e6866087db5bb3378a358c6a0b6f3de063fc12cafdd8e19bea08ebedd34ce1590fffe9097657d3aab61b81e4a8a0024801a188a1064d463da9902269388b8f5d2485b59abd0497c39096570b4fc78f3d26c7663680b8e1225158fade4aca87c050b356732bf68904eb7c300f201edbc35f6dd63639adf960ec4d0931a662c372ccf27d13d89df848e8e2f79199387eccd478d28df3c97ac36a7f16ec1d22895c929";

		let verify = VerifyCmd::parse_from(&[
			"verify",
			"--message",
			"0xabcdef",
			"--scheme",
			"dilithium2",
			signature,
			pubkey
		]);
		assert!(verify.run().is_ok());
	}
}
