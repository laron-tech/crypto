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

use crate::{Error, PublicKey, Result};
use k256::ecdsa::signature::Signer;
use rand::RngCore;

const SIZE: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrivateKeyError {
    InvalidKey,
    ErrorCrypto,
}

impl std::fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKeyError::InvalidKey => write!(f, "PrivateKey: Invalid private key"),
            PrivateKeyError::ErrorCrypto => write!(f, "PrivateKey: Error in crypto"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey(k256::SecretKey);

impl PrivateKey {
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; SIZE];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PrivateKey> {
        let secret_key = k256::SecretKey::from_be_bytes(bytes)?;
        Ok(PrivateKey(secret_key))
    }

    pub fn to_bytes(&self) -> [u8; SIZE] {
        let mut bytes = [0u8; SIZE];
        bytes.copy_from_slice(&self.0.to_be_bytes());
        bytes
    }

    pub fn sign(&self, message: &[u8]) -> Result<k256::ecdsa::recoverable::Signature> {
        let signing_key = k256::ecdsa::SigningKey::from(self.0.clone());
        let signature = signing_key.sign(message);
        Ok(signature)
    }

    pub fn public_key(&self) -> PublicKey {
        let public_key = self.0.public_key();
        PublicKey::from(public_key)
    }

    pub fn derive_child(&self, other: [u8; SIZE]) -> Result<PrivateKey> {
        let child_scalar =
            Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::from_repr(other.into()))
                .ok_or(PrivateKeyError::ErrorCrypto)?;
        let derived_scalar = self.0.to_nonzero_scalar().as_ref() + child_scalar.as_ref();
        let derived = Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(derived_scalar))
            .map(Into::into)
            .ok_or(PrivateKeyError::ErrorCrypto)?;
        Ok(PrivateKey(derived))
    }
}

impl From<k256::SecretKey> for PrivateKey {
    fn from(secret_key: k256::SecretKey) -> Self {
        PrivateKey(secret_key)
    }
}

impl From<PrivateKey> for k256::SecretKey {
    fn from(private_key: PrivateKey) -> Self {
        private_key.0
    }
}

impl From<k256::ecdsa::SigningKey> for PrivateKey {
    fn from(signing_key: k256::ecdsa::SigningKey) -> Self {
        let sk: k256::SecretKey = signing_key.into();
        PrivateKey(sk)
    }
}

impl From<PrivateKey> for k256::ecdsa::SigningKey {
    fn from(private_key: PrivateKey) -> Self {
        k256::ecdsa::SigningKey::from(private_key.0)
    }
}

impl From<[u8; SIZE]> for PrivateKey {
    fn from(bytes: [u8; SIZE]) -> Self {
        PrivateKey::from_bytes(&bytes).unwrap()
    }
}

impl From<PrivateKey> for [u8; SIZE] {
    fn from(private_key: PrivateKey) -> Self {
        private_key.to_bytes()
    }
}

impl std::str::FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != SIZE {
            return Err(PrivateKeyError::InvalidKey.into());
        }
        let mut array = [0u8; SIZE];
        array.copy_from_slice(&bytes);
        Ok(PrivateKey::from(array))
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}
