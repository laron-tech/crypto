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

use crate::{PrivateKeyError, PublicKeyError};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    v: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.v)
    }
}

impl From<k256::elliptic_curve::Error> for Error {
    fn from(err: k256::elliptic_curve::Error) -> Self {
        Error { v: err.to_string() }
    }
}

impl From<k256::ecdsa::Error> for Error {
    fn from(err: k256::ecdsa::Error) -> Self {
        Error { v: err.to_string() }
    }
}

impl From<&'static str> for Error {
    fn from(err: &str) -> Self {
        Error { v: err.to_string() }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error { v: err }
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error { v: err.to_string() }
    }
}

impl From<PrivateKeyError> for Error {
    fn from(err: PrivateKeyError) -> Self {
        Error { v: err.to_string() }
    }
}

impl From<PublicKeyError> for Error {
    fn from(err: PublicKeyError) -> Self {
        Error { v: err.to_string() }
    }
}
