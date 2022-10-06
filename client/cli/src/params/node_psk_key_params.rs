// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
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
use sc_network::config::NodePreShareKeyConfig;
use std::{path::PathBuf, str::FromStr};

use crate::{error};

/// Parameters used to create the `NodePreSharedKeyConfig`, which determines the pre shared key
/// used for libp2p networking.
#[derive(Debug, Clone, Args)]
pub struct NodePreSharedKeyParams {
	/// Endpoint for requesting a pre shared key.
	#[clap(long, value_name = "URL")]
	pub rpc_addr_for_pre_shared_key: Option<String>,
    /// The file from which to read the secret pre shared key to use for libp2p networking.
	#[clap(long, value_name = "FILE")]
	pub node_pre_shared_key_file: Option<PathBuf>,
}

impl NodePreSharedKeyParams {
	/// Create a `NodePreSharedKeyConfig` from the given `NodePreSharedKeyParams` in the context
	/// of an optional network config storage directory.
	pub fn node_pre_shared_key(&self) -> error::Result<NodePreShareKeyConfig> {
		if let Some(rpc_endpoint_for_pre_shared_key) = self.rpc_addr_for_pre_shared_key.clone() {
			Ok(
				NodePreShareKeyConfig::PRESHAREDKEY(
					sc_network::config::PreSharedKeySecret::Rpc(
						parse_url(&rpc_endpoint_for_pre_shared_key)?
					)
				)
			)
		} else if let Some(node_pre_shared_key_file) = self.node_pre_shared_key_file.clone() {
			Ok(
				NodePreShareKeyConfig::PRESHAREDKEY(
					sc_network::config::PreSharedKeySecret::File(node_pre_shared_key_file)
				)
			)
		} else {
			Err(
				error::Error::from(
					"One of the arguments must be present: --rpc-addr-for-pre-shared-key or --node-pre-shared-key-file"
				)
			)
		}
	}
}

/// Create an error caused by an invalid node key argument.
fn invalid_url(e: impl std::fmt::Display) -> error::Error {
	error::Error::Input(format!("Invalid url: {}", e))
}

/// Parse a Ed25519 secret key from a hex string into a `sc_network::Secret`.
fn parse_url(url: &str) -> error::Result<std::net::SocketAddr> {
		std::net::SocketAddr::from_str(url)
			.map_err(invalid_url)
	
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use libp2p::pnet::PreSharedKey;

	#[test]
	fn test_node_key_config_file() {
		fn check_key(file: PathBuf, key: &PreSharedKey) {
			let params = NodePreSharedKeyParams {
				node_pre_shared_key_file: Some(file),
				rpc_addr_for_pre_shared_key: None
			};

			let node_pre_shared_key = params
				.node_pre_shared_key()
				.expect("Creates node key config")
				.into_pre_share_key()
				.expect("Creates node key pair");

			if &node_pre_shared_key == key {

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
		check_key(file.clone(), &key);

		fs::write(&file, key_bytes).expect("Writes pre shared key");
		check_key(file.clone(), &key);
	}

}
