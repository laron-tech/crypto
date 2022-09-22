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

use rand::RngCore;

pub enum KeyError {
    InvalidKey,
    InvalidLength(usize, usize),
    InvalidHex,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::InvalidKey => write!(f, "Invalid key"),
            KeyError::InvalidLength(actual, expected) => write!(
                f,
                "Invalid key length. Expected {} but got {}",
                expected, actual
            ),
            KeyError::InvalidHex => write!(f, "Invalid hex"),
        }
    }
}

impl std::fmt::Debug for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Wrapper around secp256k1 secret key represented as 32-byte array.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretKey([u8; 32]);

/// Wrapper around secp256k1 public key represented as 65-byte array.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 65]);

impl SecretKey {
    /// Creates new random secret key.
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SecretKey(bytes)
    }

    /// Creates new secret key from 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(bytes)
    }

    /// Creates new secret key from slice of bytes.
    /// Panics if slice is not 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength(bytes.len(), 32));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(SecretKey(array))
    }

    /// Creates new secret key from hex string.
    /// Panics if string is not 32 bytes long.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let x = hex.trim_start_matches("0x");

        if x.len() != 64 {
            return Err(KeyError::InvalidLength(x.len(), 64));
        }

        let bytes = hex::decode(x).map_err(|_| KeyError::InvalidHex)?;
        SecretKey::from_slice(&bytes)
    }

    /// Returns secret key as 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns secret key as slice of bytes.
    pub fn to_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns secret key as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns public key corresponding to this secret key.
    pub fn public_key(&self) -> Result<PublicKey, KeyError> {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&self.0).map_err(|_| KeyError::InvalidKey)?;
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(&pk.serialize_uncompressed());
        Ok(PublicKey(bytes))
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl PublicKey {
    /// Creates new public key from 65-byte array.
    pub fn from_bytes(bytes: [u8; 65]) -> Self {
        PublicKey(bytes)
    }

    /// Creates new public key from slice of bytes.
    /// Panics if slice is not 65 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 65 {
            return Err(KeyError::InvalidLength(bytes.len(), 65));
        }
        let mut array = [0u8; 65];
        array.copy_from_slice(bytes);
        Ok(PublicKey(array))
    }

    /// Creates new public key from hex string.
    /// Panics if string is not 65 bytes long.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let x = hex.trim_start_matches("0x");

        if x.len() != 130 {
            return Err(KeyError::InvalidLength(x.len(), 130));
        }

        let bytes = hex::decode(x).map_err(|_| KeyError::InvalidHex)?;
        PublicKey::from_slice(&bytes)
    }

    /// Create new public key from secret key.
    pub fn from_secret_key(secret_key: &SecretKey) -> Result<Self, KeyError> {
        secret_key.public_key()
    }

    /// Returns public key as 65-byte array.
    pub fn to_bytes(&self) -> [u8; 65] {
        self.0
    }

    /// Returns public key as slice of bytes.
    pub fn to_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns public key as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Creates new random key pair.
pub fn new_key_pair() -> Result<(SecretKey, PublicKey), KeyError> {
    let secret_key = SecretKey::new();
    let public_key = secret_key.public_key()?;
    Ok((secret_key, public_key))
}
