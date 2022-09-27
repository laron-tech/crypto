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

use crate::{Error, PublicKey, Result};

const SIZE: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(k256::ecdsa::recoverable::Signature);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature> {
        if bytes.len() != SIZE {
            return Err("invalid signature length".into());
        }

        let sig = k256::ecdsa::recoverable::Signature::try_from(bytes)?;
        Ok(Signature(sig))
    }

    pub fn to_bytes(&self) -> [u8; SIZE] {
        let mut bytes = [0u8; SIZE];
        bytes.copy_from_slice(self.0.as_ref());
        bytes
    }

    pub fn verify(&self, msg: &[u8], public_key: &PublicKey) -> Result<bool> {
        let verifying_key: PublicKey = self.0.recover_verifying_key(msg)?.into();
        if verifying_key != *public_key {
            return Err("invalid signature".into());
        }
        Ok(true)
    }

    pub fn recover(&self, msg: &[u8]) -> Result<PublicKey> {
        let verifying_key: PublicKey = self.0.recover_verifying_key(msg)?.into();
        Ok(verifying_key)
    }
}

impl From<k256::ecdsa::recoverable::Signature> for Signature {
    fn from(sig: k256::ecdsa::recoverable::Signature) -> Self {
        Signature(sig)
    }
}

impl From<Signature> for k256::ecdsa::recoverable::Signature {
    fn from(sig: Signature) -> Self {
        sig.0
    }
}

impl From<Signature> for [u8; SIZE] {
    fn from(sig: Signature) -> Self {
        sig.to_bytes()
    }
}

impl From<[u8; SIZE]> for Signature {
    fn from(bytes: [u8; SIZE]) -> Self {
        Signature::from_bytes(&bytes).unwrap()
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Signature::from_bytes(&bytes)
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}
