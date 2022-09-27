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
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

const SIZE: usize = 20;

/// Address represents 20 bytes of ethereum address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address([u8; SIZE]);

impl Address {
    /// Create a new address from a the given bytes.
    pub fn new(bytes: [u8; SIZE]) -> Self {
        Address(bytes)
    }

    /// Create a new address from a bytes slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIZE {
            return Err("Address: invalid length".into());
        }

        let mut address = [0u8; SIZE];
        address.copy_from_slice(bytes);
        Ok(Address(address))
    }

    /// Create a new address from public key.
    pub fn from_public_key(public_key: &PublicKey) -> Address {
        let bytes = public_key.to_uncompressed_bytes();
        let mut buf = [0u8; 32];
        let mut keccak = Keccak::v256();
        keccak.update(&bytes[1..]);
        keccak.finalize(&mut buf);

        let mut address = [0u8; SIZE];
        address.copy_from_slice(&buf[12..]);
        Address(address)
    }

    /// Return the address as bytes.
    pub fn to_bytes(&self) -> [u8; SIZE] {
        self.0
    }

    /// Return the address as checksummed string.
    pub fn to_hex(&self) -> String {
        let hex_addr = hex::encode(&self.0);
        let mut hasher = tiny_keccak::Keccak::v256();
        hasher.update(hex_addr.as_bytes());
        let mut buf = [0u8; 32];
        hasher.finalize(&mut buf);

        let addr_hash = hex::encode(&buf);

        hex_addr
            .char_indices()
            .fold(String::from("0x"), |mut x, (i, c)| {
                let n = u16::from_str_radix(&addr_hash[i..i + 1], 16).unwrap();
                if n > 7 {
                    x.push(c.to_ascii_uppercase());
                } else {
                    x.push(c);
                }
                x
            })
    }
}

impl From<[u8; SIZE]> for Address {
    fn from(bytes: [u8; SIZE]) -> Self {
        Address(bytes)
    }
}

impl From<Address> for [u8; SIZE] {
    fn from(address: Address) -> Self {
        address.0
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim_start_matches("0x");

        let bytes = hex::decode(s)?;
        let mut address = [0u8; SIZE];
        address.copy_from_slice(&bytes);
        Ok(Address(address))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
