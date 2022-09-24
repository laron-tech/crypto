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

use std::fmt;

/// Error type for the keys module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidHexString,
    InvalidPrivateKey,
    InvalidPublicKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidHexString => write!(f, "Invalid hex string"),
            Error::InvalidPrivateKey => write!(f, "Invalid private key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error() {
        assert_eq!(
            Error::InvalidHexString.to_string(),
            "Invalid hex string".to_string()
        );
        assert_eq!(
            Error::InvalidPrivateKey.to_string(),
            "Invalid private key".to_string()
        );
        assert_eq!(
            Error::InvalidPublicKey.to_string(),
            "Invalid public key".to_string()
        );
    }
}
