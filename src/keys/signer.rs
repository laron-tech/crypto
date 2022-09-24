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

use k256::ecdsa::recoverable::Signature;

use super::{PrivateKey, PublicKey};

/// Sign a message with a private key
/// # Example
/// ```
/// use laron_crypto::keys::{PrivateKey, PublicKey, signer};
///
/// let private_key = PrivateKey::new();
/// let public_key = PublicKey::from_private(&private_key);
/// let message = b"Hello, World!";
/// let signature = signer::sign(message, &private_key);
/// assert!(public_key.verify(message, &signature));
/// ```
pub fn sign(msg: &[u8], key: &PrivateKey) -> Signature {
    key.sign(msg)
}

/// Verify a message with a public key
/// # Example
/// ```
/// use laron_crypto::keys::{PrivateKey, PublicKey, signer};
///
/// let private_key = PrivateKey::new();
/// let public_key = PublicKey::from_private(&private_key);
/// let message = b"Hello, World!";
/// let signature = signer::sign(message, &private_key);
/// assert!(signer::verify(message, &signature, &public_key));
/// ```
pub fn verify(msg: &[u8], signature: &Signature, pub_key: &PublicKey) -> bool {
    pub_key.verify(msg, signature)
}

/// Recover a public key from a message and a signature
/// # Example
/// ```
/// use laron_crypto::keys::{PrivateKey, PublicKey, signer};
///
/// let private_key = PrivateKey::new();
/// let public_key = PublicKey::from_private(&private_key);
/// let message = b"Hello, World!";
/// let signature = signer::sign(message, &private_key);
/// assert_eq!(signer::recover(message, &signature).unwrap(), public_key);
/// ```
pub fn recover(msg: &[u8], signature: &Signature) -> Option<PublicKey> {
    let rec = signature.recover_verifying_key(msg).unwrap();
    let pk = PublicKey::from_slice(&rec.to_bytes()).unwrap();
    Some(pk)
}
