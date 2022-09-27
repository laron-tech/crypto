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

use std::str::FromStr;

use crate::{Error, PrivateKey, Result, Signature};
use k256::elliptic_curve::{group::prime::PrimeCurveAffine, sec1::ToEncodedPoint};

const SIZE: usize = 33;
const UNCOMPRESSED_SIZE: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyError {
    InvalidKey,
    ErrorCrypto,
}

impl std::fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicKeyError::InvalidKey => write!(f, "PublicKey: Invalid public key"),
            PublicKeyError::ErrorCrypto => write!(f, "PublicKey: Error in crypto"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(k256::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey> {
        let pk = k256::PublicKey::from_sec1_bytes(bytes)?;
        Ok(PublicKey(pk))
    }

    pub fn to_bytes(&self) -> [u8; SIZE] {
        let mut bytes = [0u8; SIZE];
        let verifying_key: k256::ecdsa::VerifyingKey = self.0.into();
        bytes.copy_from_slice(&verifying_key.to_bytes());
        bytes
    }

    pub fn to_uncompressed_bytes(&self) -> [u8; UNCOMPRESSED_SIZE] {
        let verifying_key: k256::ecdsa::VerifyingKey = self.0.into();
        let point = verifying_key.to_encoded_point(false);
        let mut bytes = [0u8; UNCOMPRESSED_SIZE];
        bytes.copy_from_slice(&point.to_bytes());
        bytes
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<bool> {
        sig.verify(msg, self)
    }

    pub fn recover(&self, msg: &[u8], sig: &Signature) -> Result<PublicKey> {
        let pk = sig.recover(msg)?;
        Ok(PublicKey(pk.into()))
    }

    pub fn derive_child(&self, other: [u8; 32]) -> Result<PublicKey> {
        let child_scalar =
            Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::from_repr(other.into()))
                .ok_or(PublicKeyError::InvalidKey)?;
        let child_point = self.0.to_projective() + (k256::AffinePoint::generator() * *child_scalar);
        let derived = k256::PublicKey::from_affine(child_point.into())
            .map_err(|_| PublicKeyError::ErrorCrypto)?;
        Ok(PublicKey(derived))
    }
}

impl From<k256::PublicKey> for PublicKey {
    fn from(key: k256::PublicKey) -> Self {
        PublicKey(key)
    }
}

impl From<PublicKey> for k256::PublicKey {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

impl From<k256::ecdsa::VerifyingKey> for PublicKey {
    fn from(key: k256::ecdsa::VerifyingKey) -> Self {
        PublicKey(key.into())
    }
}

impl From<PublicKey> for k256::ecdsa::VerifyingKey {
    fn from(key: PublicKey) -> Self {
        key.0.into()
    }
}

impl From<[u8; SIZE]> for PublicKey {
    fn from(bytes: [u8; SIZE]) -> Self {
        PublicKey::from_bytes(&bytes).unwrap()
    }
}

impl From<PublicKey> for [u8; SIZE] {
    fn from(key: PublicKey) -> Self {
        key.to_bytes()
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(key: PrivateKey) -> Self {
        key.public_key()
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        PublicKey::from_bytes(&bytes)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}
