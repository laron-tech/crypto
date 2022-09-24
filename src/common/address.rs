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

use tiny_keccak::Hasher;

use crate::keys::PublicKey;

use super::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct Address([u8; 20]);

/// # Address
/// This struct contains the address of the public key.
/// ## Example
/// ```rust
/// use laron_crypto::common::Address;
/// use laron_crypto::keys::PublicKey;
/// use laron_crypto::keys::PrivateKey;
///
/// let private_key = PrivateKey::new();
/// let public_key = PublicKey::from_private(&private_key);
/// let address = Address::from_public(&public_key);
/// ```
impl Address {
    /// Create address from fixed bytes.
    /// is not valid.
    /// ## Example
    /// ```rust
    /// use laron_crypto::common::Address;
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let address = Address::from_public(&public_key);
    /// let address_from_bytes = Address::new(address.to_bytes());
    /// assert_eq!(address, address_from_bytes);
    /// ```
    pub fn new(addr: [u8; 20]) -> Self {
        Address(addr)
    }

    /// Create address from slice of bytes.
    /// This function will return an error if the slice of bytes is not valid.
    /// ## Example
    /// ```rust
    /// use laron_crypto::common::Address;
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let address = Address::from_public(&public_key);
    /// let address_from_bytes = Address::from_slice(&address.to_bytes()).unwrap();
    /// assert_eq!(address, address_from_bytes);
    /// ```
    pub fn from_slice(addr: &[u8]) -> Result<Self, Error> {
        if addr.len() != 20 {
            return Err(Error::InvalidAddress);
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(addr);
        Ok(Address(a))
    }

    /// Create address from public key.
    /// ## Example
    /// ```rust
    /// use laron_crypto::common::Address;
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let address = Address::from_public(&public_key);
    /// ```
    pub fn from_public(pubkey: &PublicKey) -> Self {
        let pk_bytes = pubkey.to_bytes_uncompressed();
        let mut buf = [0u8; 32];
        let mut hasher = tiny_keccak::Keccak::v256();
        hasher.update(&pk_bytes[1..]);
        hasher.finalize(&mut buf);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&buf[12..]);

        Address(addr)
    }

    /// Convert address into checksummed hex string.
    /// ## Example
    /// ```rust
    /// use laron_crypto::common::Address;
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let address = Address::from_public(&public_key);
    /// let address_hex = address.to_hex();
    /// ```
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

    /// Return address as str.
    /// ## Example
    /// ```rust
    /// use laron_crypto::common::Address;
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let address = Address::from_public(&public_key);
    /// let address_str = address.as_str();
    /// ```
    pub fn as_str(&self) -> &'static str {
        let string = self.to_hex();
        Box::leak(string.into_boxed_str())
    }

    /// Return address as bytes fixed bytes.
    /// ## Example
    /// ```rust
    /// use laron_crypto::common::Address;
    /// use laron_crypto::keys::PublicKey;
    /// use laron_crypto::keys::PrivateKey;
    ///
    /// let private_key = PrivateKey::new();
    /// let public_key = PublicKey::from_private(&private_key);
    /// let address = Address::from_public(&public_key);
    /// let address_bytes = address.to_bytes();
    /// ```
    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl fmt::UpperHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode_upper(&self.0))
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl From<[u8; 20]> for Address {
    fn from(addr: [u8; 20]) -> Self {
        Address(addr)
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches("0x");
        let addr = hex::decode(s).map_err(|_| Error::InvalidAddress)?;
        Address::from_slice(&addr)
    }
}
