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

//! # Laron Crypto
//! Laron Crypto is a library for signing and verifying messages using Secp256k1 elliptic curve
//! algorithm.
//!
//! This library is a wrapper for [k256](https://docs.rs/crate/k256/0.11.5) crate.
//! This library also provides a simple way to generate a private key and a public key. and also a
//! valid ethereum address.
//!
//! ## Example
//! ```rust
//! use laron_crypto::{keys::*, common::*};
//!
//! // Generate a new private key and a public key
//! let sk = PrivateKey::new();
//! let pk = sk.public();
//!
//! // Generate a valid ethereum address from the public key
//! let addr = Address::from_public(&pk);
//!
//! // Sign a message
//! let msg = b"Hello World!";
//! let sig = sk.sign(msg);
//! assert!(pk.verify(msg, &sig));
//!
//! // or use other way
//! let sig = signer::sign(msg, &sk);
//! assert!(signer::verify(msg, &sig, &pk));
//!
//! // Recover the public key from the signature
//! let recovered_pk = signer::recover(msg, &sig).unwrap();
//! assert_eq!(pk, recovered_pk);
//! ```

pub mod common;
pub mod keys;
