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

use secp256k1::{
    ecdsa::{self, RecoverableSignature},
    Error, Message,
};
use tiny_keccak::Hasher;

mod keys;
pub use keys::*;

/// Calculate and return keccak-256 hash of the given input.
/// # Input
/// * `input` - The input to be hashed in byte slices.
/// # Returns
/// * `hash` - The keccak-256 hash of the input.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut buf);
    buf
}

/// Calculate and return keccak-512 hash of the given input.
/// # Input
/// * `input` - The input to be hashed in byte slices.
/// # Returns
/// * `hash` - The keccak-512 hash of the input.
pub fn keccak512(input: &[u8]) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let mut hasher = tiny_keccak::Keccak::v512();
    hasher.update(input);
    hasher.finalize(&mut buf);
    buf
}

pub type Signature = RecoverableSignature;

/// Sign a message with the given secret key and return the recoverable signature.
pub fn sign(msg: &[u8], secret_key: SecretKey) -> Result<Signature, Error> {
    let secp = secp256k1::Secp256k1::new();
    let hash = keccak256(msg);
    let msg_bytes = Message::from_slice(&hash)?;
    let sk = secp256k1::SecretKey::from_slice(secret_key.to_slice())?;
    let sig = secp.sign_ecdsa_recoverable(&msg_bytes, &sk);
    Ok(sig)
}

/// Verify a signature with the given public key and message.
pub fn verify(sig: &Signature, pub_key: &PublicKey, msg: &[u8]) -> Result<bool, Error> {
    let secp = secp256k1::Secp256k1::new();
    let hash = keccak256(msg);
    let msg_bytes = Message::from_slice(&hash)?;
    let pk = secp256k1::PublicKey::from_slice(pub_key.to_slice())?;
    let sig = ecdsa::Signature::from_compact(&sig.serialize_compact().1)?;

    let verif = secp.verify_ecdsa(&msg_bytes, &sig, &pk);
    Ok(verif.is_ok())
}

/// Recover the public key from the signature and message.
pub fn ecrecover(msg: &[u8], sig: &Signature) -> Result<PublicKey, Error> {
    let secp = secp256k1::Secp256k1::new();
    let hash = keccak256(msg);
    let msg_bytes = Message::from_slice(&hash)?;
    let pk = secp.recover_ecdsa(&msg_bytes, sig)?;
    let pub_key = PublicKey::from_slice(&pk.serialize_uncompressed());

    match pub_key {
        Ok(pk) => Ok(pk),
        Err(_) => Err(Error::InvalidPublicKey),
    }
}

#[cfg(test)]
mod crypto_test {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (sk, pk) = new_key_pair().unwrap();
        let msg = b"hello world";
        let sig = sign(msg, sk).unwrap();
        assert!(verify(&sig, &pk, msg).unwrap());
    }

    #[test]
    fn test_ecrecover() {
        let (sk, pk) = new_key_pair().unwrap();
        let msg = b"hello world";
        let sig = sign(msg, sk).unwrap();
        let pk2 = ecrecover(msg, &sig).unwrap();
        assert_eq!(pk, pk2);
    }
}
