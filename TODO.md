# ToDo

*Note* We should reimplement the PIN verification mechanism as we don't trust proprietary stuff. Especially because it may be implemented poorly on different card models.

*Note* We should also implement our own secure communication protocol, same reasons.

- secure communication protocol (auth-enc), probably using DH
- store 32-byte secret(s)
- set 32-byte "pin code" (tagged_hash("CardUnlock", device_secret || pin_code))
- get 32-byte secret(s)
- get status - uninitialized, unlocked, locked, permanently locked
- get pin counter <current_counter><max_counter>
- anti-tamper challenge -> 32-byte challenge -> sign with secret -> ecdsa signature
- anti-tamper counter
- ripemd160 lib? - we need it for xpub fingerprints, but it's not must-have