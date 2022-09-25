# LARON-CRYPTO
![build](https://github.com/laron-tech/crypto/actions/workflows/rust.yml/badge.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![crates.io](https://img.shields.io/crates/v/laron-crypto.svg)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Flaron-tech%2Fcrypto.svg?type=small)](https://app.fossa.com/projects/git%2Bgithub.com%2Flaron-tech%2Fcrypto?ref=badge_small)

## Laron Crypto
Laron Crypto is a library for signing and verifying messages using Secp256k1 elliptic curve
algorithm.

This library is a wrapper for [k256](https://docs.rs/crate/k256/0.11.5) crate.
This library also provides a simple way to generate a private key and a public key. and also a
valid ethereum address.

### Example
```rust
use laron_crypto::{keys::*, common::*};

// Generate a new private key and a public key
let sk = PrivateKey::new();
let pk = sk.public();

// Generate a valid ethereum address from the public key
let addr = Address::from_public(&pk);

// Sign a message
let msg = b"Hello World!";
let sig = sk.sign(msg);
assert!(pk.verify(msg, &sig));

// or use other way
let sig = signer::sign(msg, &sk);
assert!(signer::verify(msg, &sig, &pk));

// Recover the public key from the signature
let recovered_pk = signer::recover(msg, &sig).unwrap();
assert_eq!(pk, recovered_pk);
```

[documentation](https://docs.rs/laron-crypto/latest)

## Usage
```toml
[dependencies]
laron-crypto = "0.1"
```


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Flaron-tech%2Fcrypto.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Flaron-tech%2Fcrypto?ref=badge_large)
