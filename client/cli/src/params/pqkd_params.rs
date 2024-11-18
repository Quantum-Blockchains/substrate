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
use sc_network::config::PqkdConfig;

/// Parameters used to create the `PqkdConfig`, which determines the pqkd
/// used for libp2p networking.
#[derive(Debug, Clone, Args)]
pub struct PqkdParams {
	/// SAE_ID of local pqkd
	#[clap(long, value_name = "SAE_ID")]
	pub sae_id: String,

	/// Address to lokal pqkd
	#[clap(long, value_name = "ADDR")]
	pub addr_pqkd: String,

	/// Address to qrng API
	#[clap(long, value_name = "ADDR")]
	pub addr_qrng: String,
}

impl PqkdParams {
	/// Create a 'PqkdConfig' from the given 'PqkdParams'
	pub fn pqkd_config(&self) -> PqkdConfig {
		PqkdConfig { sae_id: self.sae_id.clone(), addr_pqkd: self.addr_pqkd.clone(), addr_qrng: self.addr_qrng.clone() }
	}
}