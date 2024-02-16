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

use clap::Args;
use sc_network::config::PreSharedKeyConfig;
use std::path::PathBuf;

const PRE_SHARED_KEY_FILE: &str = "pre_shared_key";

/// Parameters used to create the `PreSharedKeyConfig`, which determines the pre shared key
/// used for libp2p networking.
#[derive(Debug, Clone, Args)]
pub struct PreSharedKeyParams {
	/// Path to file with pre-shared key.
	#[clap(long, value_name = "FILE")]
	pub psk_file: Option<PathBuf>,
}

impl PreSharedKeyParams {
	/// Create a `PreSharedKeyConfig` from the given `PreSharedKeyParams` in the context
	/// of an optional network config storage directory.
	pub fn pre_shared_key(&self, net_config_dir: &PathBuf) -> PreSharedKeyConfig {
		PreSharedKeyConfig {
			pre_shared_key: sc_network::config::PreSharedKeySecret::File(
					self.psk_file
					.clone()
					.unwrap_or_else(|| net_config_dir.join(PRE_SHARED_KEY_FILE)),
				)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use libp2p::pnet::PreSharedKey;

	#[test]
	fn test_pre_shared_key_config_file() {
		fn check_pre_shared_key(file: PathBuf, key: &PreSharedKey) {
			let params = PreSharedKeyParams {
				psk_file: Some(file)
			};

			let pre_shared_key = params
				.pre_shared_key(&PathBuf::from("not-used"))
				.into_pre_share_key()
				.expect("Creates node key pair");

			if &pre_shared_key == key {

			} else {
				panic!("Invalid key");
			}
		}

		let tmp = tempfile::Builder::new().prefix("alice").tempdir().expect("Creates tempfile");
		let file = tmp.path().join("mysecret").to_path_buf();
		let key_bytes: [u8;32] = [24, 97, 125, 255, 78, 254, 242, 4, 80, 221, 94, 175, 192, 96, 253,
		133, 250, 172, 202, 19, 217, 90, 206, 59, 218, 11, 227, 46, 70, 148, 252, 215];
		let key = PreSharedKey::new(
			key_bytes
		);

		fs::write(&file, hex::encode(key_bytes.as_ref())).expect("Writes pre shared key");
		check_pre_shared_key(file.clone(), &key);
	}

}
