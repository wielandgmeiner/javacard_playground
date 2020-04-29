# ToDo

*Note* We should double-check the PIN as we don't trust proprietary stuff. Especially because it may be implemented poorly on different card models.

We can encrypt all secret data in the card with a key derived from internal secret and the PIN code, so even if PIN check is bypassed secrets are invalid.

- check buffer overwrites in functions - when output buffer is the same as input mb with an offset
- reestablish SC without PIN lock
- anti-tamper challenge -> 32-byte challenge -> sign with secret -> ecdsa signature
- anti-tamper counter
- ripemd160 - we need it for xpub fingerprints, but it's not must-have. Currently using Ledger lib => license is tricky
- transaction parsing and signing - screw legacy, use segwit only

# Transaction signing

To calculate hash for signing we need transaction context:
- version: 4 bytes
- hash_prevouts: 32 bytes, in: num_inp * (32 txid + 4 index)
- hash_sequence: 32 bytes, in: num_inp * 4
- hash_outputs:  32 bytes, in: num_outs * (<=33 script_pubkey, 8 value)
- locktime: 4 bytes

# Helper functions

- Available features - check what algorithms are available and use them

# Math

Several important things to implement:
- [ ] bip39 mnemonic + password to seed:
  - [x] pbkdf2-hmac-sha512, limited to 64 byte output
- [x] bip32 private key derivation:
- [x] bip32 public key derivation:

pbkdf2-hmac-sha512:
  - sha512 is supported
  - hmac is implement for arbitrary hash functions
  - due to 2048 rounds this algorithm is increadibly slow (70 seconds), so makes sense to use it only if we really-really-really need it. Otherwise default seed with empty password can be cached and used.

# Secure communication

At the moment we use x-coordinate of ECDH for shared key and `ALG_AES_CBC_ISO9797_M2` as AEAD scheme.

We should switch to `Noise_secp256k1_ChaChaPoly_SHA256`. Concerns here - homebrew implementation of chacha20poly1305 might be vulnerable to attacks. Would it be better to use AES_CBC with SHA256?

In any case key rotation is important, so Noise for sure.