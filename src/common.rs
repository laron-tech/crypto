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

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use laron_primitives::{U160, U256};

use crate::crypto::{keccak256, PublicKey};

pub enum Error {
    InvalidHex,
    InvalidLength(usize, usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidHex => write!(f, "Invalid hex"),
            Error::InvalidLength(actual, expected) => write!(
                f,
                "Invalid length: actual={}, expected={}",
                actual, expected
            ),
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// 20-bytes of ethereum address.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address([u8; 20]);

impl Address {
    /// Create new address from 20-bytes array.
    pub fn new(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Create new address from PublicKey.
    pub fn from_public_key(pk: PublicKey) -> Self {
        let pkb = pk.to_bytes();
        let hash = keccak256(&pkb[1..]);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[12..32]);
        Address(bytes)
    }

    /// Convert U160 to Address.
    /// # Input
    /// `u160` - U160 value.
    pub fn from_u160(v: U160) -> Self {
        let bytes = v.to_be_bytes();
        Address::new(bytes)
    }

    /// Convert Address to U160.
    pub fn to_u160(&self) -> U160 {
        U160::from_be_bytes(self.0)
    }

    /// Create new address from hex string.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        if bytes.len() != 20 {
            return Err(Error::InvalidLength(bytes.len(), 20));
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);
        Ok(Address::new(address))
    }

    /// Convert address to hex string.
    pub fn to_hex(&self) -> String {
        self.cheksum()
    }

    /// Convert address to checksummed hex string.
    pub fn cheksum(&self) -> String {
        let hex_addr = hex::encode(&self.0);

        let addr_hash = hex::encode(keccak256(hex_addr.as_bytes()));

        hex_addr
            .char_indices()
            .fold(String::from("0x"), |mut x, (i, c)| {
                let n = u16::from_str_radix(&addr_hash[i..i + 1], 16).unwrap();

                if n > 7 {
                    x.push_str(&c.to_uppercase().to_string());
                } else {
                    x.push_str(&c.to_string());
                }

                x
            })
    }

    /// Returns address as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert address to bytes.
    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    /// Returns zero address.
    pub fn zero() -> Self {
        Address([0u8; 20])
    }
}

impl From<String> for Address {
    fn from(s: String) -> Self {
        Address::from_hex(&s).unwrap()
    }
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        Address::from_hex(s).unwrap()
    }
}

impl From<U160> for Address {
    fn from(v: U160) -> Self {
        Address::from_u160(v)
    }
}

impl From<Address> for U160 {
    fn from(v: Address) -> Self {
        v.to_u160()
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Address) -> Ordering {
        self.to_u160().cmp(&other.to_u160())
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Address) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Address::from_hex(&s).unwrap())
    }
}

/// 32-bytes of ethereum hash.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Create new hash from 32-bytes array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create new hash from hex string.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(Error::InvalidLength(bytes.len(), 32));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Hash::new(hash))
    }

    /// Convert hash to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns hash as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert hash to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns zero hash.
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }
}

impl From<String> for Hash {
    fn from(s: String) -> Self {
        Hash::from_hex(&s).unwrap()
    }
}

impl From<&str> for Hash {
    fn from(s: &str) -> Self {
        Hash::from_hex(s).unwrap()
    }
}

impl From<U256> for Hash {
    fn from(v: U256) -> Self {
        Self::new(v.to_be_bytes())
    }
}

impl From<Hash> for U256 {
    fn from(v: Hash) -> Self {
        U256::from_be_bytes(v.0)
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        let x = U256::from_be_bytes(self.0);
        let y = U256::from_be_bytes(other.0);
        x.cmp(&y)
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Hash::from_hex(&s).unwrap())
    }
}
