# ToDo

*Note* We should double-check the PIN as we don't trust proprietary stuff. Especially because it may be implemented poorly on different card models.
We can encrypt all secret data in the card with a key derived from internal secret and the PIN code, so even if PIN check is bypassed secrets are invalid.

- reestablish SC without PIN lock
- anti-tamper challenge -> 32-byte challenge -> sign with secret -> ecdsa signature
- anti-tamper counter
- ripemd160 lib? - we need it for xpub fingerprints, but it's not must-have

# Math

Several important things to implement:
- bip39 mnemonic + password to seed:
  - pbkdf2-hmac-sha512, maybe only limited to 64 byte output
- bip32 private key derivation:
  - hmac-sha512
  - field element modulo addition
  - have to be sidechannel resistant
- bip32 public key derivation:
  - hmac-sha512
  - point addition

pbkdf2-hmac-sha512:
  - sha512 is supported
  - hmac is already implement for arbitrary hash functions
  - pbkdf2 with 64-byte out can be implemented easily
  - it's increadibly slow (a few minutes), so makes sense to implement it only if we really-really-really need it.

```py
# https://en.wikipedia.org/wiki/PBKDF2
# for 64-byte output can be simplified further
def pbkdf2_hmac_sha512(password, salt, iterations:int, bytes_to_read:int):
    # xor two arrays
    def binxor(a, b):
        return bytes([x ^ y for (x, y) in zip(a, b)])
    # convert to bytes
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    # result
    r = b''
    # no need in the loop if bytes_to_read <= 64
    # just set i = 1
    for i in range(1,bytes_to_read//64+1+int(bool(bytes_to_read%64))):
        U = hmac.new(password, salt + i.to_bytes(4,'big'), digestmod=hashlib.sha512).digest()
        result = U
        for j in range(2, 1+iterations):
            U = hmac.new(password, U, digestmod=hashlib.sha512).digest()
            result = binxor(result, U)
        r += result
    return r[:bytes_to_read]
```



# Secure communication

At the moment we use x-coordinate of ECDH for shared key and `ALG_AES_CBC_ISO9797_M2` as AEAD scheme.

We should switch to `Noise_secp256k1_ChaChaPoly_SHA256`. Concerns here - homebrew implementation of chacha20poly1305 might be vulnerable to attacks. Would it be better to use AES_CBC with SHA256?

In any case key rotation is important, so Noise for sure.