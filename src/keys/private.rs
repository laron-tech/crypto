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

use std::{fmt, str::FromStr};

use k256::ecdsa::{recoverable::Signature, signature::Signer, SigningKey};
use rand::RngCore;

use super::{error::Error, public::PublicKey};

/// # Private Key
/// This struct contains the private key for the signing message and generating
/// the public key.
///
/// ## Example
/// ```rust
/// use laron_crypto::keys::PrivateKey;
///
/// let private_key = PrivateKey::new();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey(SigningKey);

impl PrivateKey {
    /// Generate a new random private key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// ```
    pub fn new() -> PrivateKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        PrivateKey(SigningKey::from_bytes(&bytes).unwrap())
    }

    /// Generate a new private key from a slice of bytes.
    /// This function will return an error if the slice of bytes is not 32 bytes.
    ///
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let private_key_from_bytes = PrivateKey::from_slice(&private_key.to_bytes()).unwrap();
    /// assert_eq!(private_key, private_key_from_bytes);
    /// ```
    pub fn from_slice(bytes: &[u8]) -> Result<PrivateKey, Error> {
        let key = SigningKey::from_bytes(bytes).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(PrivateKey(key))
    }

    /// Convert the private key to a slice of bytes.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let bytes = private_key.to_bytes(); // [u8; 32]
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.0.to_bytes().as_ref());
        bytes
    }

    /// Return the bytes of the private key as vector.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let bytes = private_key.as_bytes(); // Vec<u8>
    /// ```
    pub fn as_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Return str representation of the private key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let str = private_key.as_str(); // &str
    /// ```
    pub fn as_str(&self) -> &'static str {
        let string = format!("{:x}", self);
        Box::leak(string.into_boxed_str())
    }

    /// Return the public key of the private key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = private_key.public();
    /// ```
    pub fn public(&self) -> PublicKey {
        PublicKey::from_private(self)
    }

    /// Sign a message with the private key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let msg = b"Hello, world!";
    /// let private_key = PrivateKey::new();
    /// let signature = private_key.sign(msg);
    /// ```
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }
}

impl Default for PrivateKey {
    fn default() -> PrivateKey {
        PrivateKey::new()
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey \"{:x}\"", self)
    }
}

impl fmt::UpperHex for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.to_bytes()))?;

        Ok(())
    }
}

impl fmt::LowerHex for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))?;

        Ok(())
    }
}

impl fmt::Binary for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter() {
            write!(f, "{:08b}", byte)?;
        }

        Ok(())
    }
}

impl fmt::Octal for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter() {
            write!(f, "{:03o}", byte)?;
        }

        Ok(())
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHexString)?;

        PrivateKey::from_slice(&bytes)
    }
}
