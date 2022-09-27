// This file is part of the laron-crypto.
//
// Copyright (C) 2022 Ade M Ramdani
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! ![build](https://github.com/laron-tech/crypto/actions/workflows/rust.yml/badge.svg)
//! [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
//! ![crates.io](https://img.shields.io/crates/v/laron-crypto.svg)
//! [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Flaron-tech%2Fcrypto.svg?type=small)](https://app.fossa.com/projects/git%2Bgithub.com%2Flaron-tech%2Fcrypto?ref=badge_small)
//!
//! Laron Crypto is a library wrapper for the [k256](https://docs.rs/k256/latest/k256/) which
//! simplifies the usage of the library and provides a more user-friendly API.
//! The library is intended to be used for signing and verifying messages using
//! the Elliptic Curve Digital Signature Algorithm (ECDSA).
//! And also provides a simple API for generating a key pair for Ethereum account.

mod error;
pub use error::*;

mod keys;
pub use keys::*;

mod common;
pub use common::*;
