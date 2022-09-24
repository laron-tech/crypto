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

use k256::ecdsa::{recoverable::Signature, SigningKey, VerifyingKey};

use super::{error::Error, PrivateKey};

/// # Public Key
/// This struct contains the public key for the verification of the message.
/// ## Example
/// ```rust
/// use laron_crypto::keys::PublicKey;
/// use laron_crypto::keys::PrivateKey;
///
/// let private_key = PrivateKey::new();
/// let public_key = PublicKey::from_private(&private_key);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Create public key from slice of bytes.
    /// This function will return an error if the slice of bytes is not valid.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let public_key_from_bytes = PublicKey::from_slice(&public_key.as_bytes()).unwrap();
    /// assert_eq!(public_key, public_key_from_bytes);
    /// ```
    pub fn from_slice(bytes: &[u8]) -> Result<PublicKey, Error> {
        let key = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(PublicKey(key))
    }

    /// Create public key from private key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// ```
    pub fn from_private(private_key: &PrivateKey) -> PublicKey {
        let bytes = private_key.to_bytes();
        let sk = SigningKey::from_bytes(&bytes).unwrap();
        PublicKey(VerifyingKey::from(&sk))
    }

    /// Return the compressed public key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    ///
    /// let compressed = public_key.to_bytes();
    /// assert_eq!(compressed.len(), 33);
    /// ```
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(&self.0.to_bytes());
        bytes
    }

    /// Return the uncompressed public key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let uncompressed = public_key.to_bytes_uncompressed();
    /// assert_eq!(uncompressed.len(), 65);
    /// ```
    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.0.to_bytes_uncompressed().to_vec()
    }

    /// Return the public key as a vector of bytes.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let bytes = public_key.as_bytes();
    /// assert_eq!(bytes.len(), 33);
    /// ```
    pub fn as_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Return the public key as a string.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let string = public_key.as_str();
    /// assert_eq!(string.len(), 66);
    /// ```
    pub fn as_str(&self) -> &'static str {
        let string = format!("{:x}", self);
        Box::leak(string.into_boxed_str())
    }

    /// Verify the signature of the message.
    /// ## Example
    /// ```rust
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let message = b"Hello World";
    /// let signature = private_key.sign(message);
    /// assert!(public_key.verify(message, &signature));
    /// ```
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let rec = signature.recover_verifying_key(msg).unwrap();
        self.0 == rec
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey \"{:x}\"", self)
    }
}

impl fmt::UpperHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.to_bytes()))?;

        Ok(())
    }
}

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))?;

        Ok(())
    }
}

impl fmt::Binary for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter() {
            write!(f, "{:08b}", byte)?;
        }

        Ok(())
    }
}

impl fmt::Octal for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter() {
            write!(f, "{:03o}", byte)?;
        }

        Ok(())
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHexString)?;

        PublicKey::from_slice(&bytes)
    }
}
