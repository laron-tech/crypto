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

//! This module contains the public and private key types.
//!
//! The public key is used to verify signatures, while the private key is used to
//! sign messages.
//!
//! # Example
//! ```rust
//! use laron_crypto::{PrivateKey, PublicKey};
//!
//! let private_key = PrivateKey::random();
//! let public_key = PublicKey::from(&private_key);
//!
//! let message = b"Hello, world!";
//! let signature = private_key.sign(message);
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```
//!
//! It is also can be used for ethereum address generation.
//!
//! # Example
//! ```rust
//! use laron_crypto::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! // create address
//! let address = private_key.public_key().address();
//! ```

mod private_key;
pub use private_key::*;

mod public_key;
pub use public_key::*;

mod signature;
pub use signature::Signature;
