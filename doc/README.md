# Applets

## `Teapot`

A very simple "Hello world" class that doesn't use any PIN protection or secure communication. It can only store up to `255` bytes of data and give it back on request. Perfect for testing communication with the card.

By default the phrase is `I am a teapot gimme some tea plz`.

[API docs](./Teapot.md)

## `MemoryCard`

Extends `Teapot`, adds PIN protection and secure communication.

Also has a unique secret that can do HMAC-SHA256 for 100 arbitrary messages while locked (without PIN) - it can be used as an tamper countermeasure to make sure that the applet and card is not swapped to a different one.

[API docs](./MemoryCard.md)

## `BlindOracle`

Extends `MemoryCard`. Adds `secp256k1` signing functionality.

Adds another slot for a key of max `255` bytes that is write-only - you can load a key to this slot or generate one on the card, and then use bip39 / bip32 to derive new keys, and sign arbitrary messages.

Includes nonce blinding protocol to minimize trust in proprietary stuff deployed on the card.

Also has a unique secret that can sign up to 100 arbitrary messages while locked (without PIN) - it can be used as an tamper countermeasure to make sure that the applet and card is not swapped to a different one.

Curve - `secp256k1`, signature - `ECDSA`. Schnorr further in the future.

[API docs](./BlindOracle.md)

## `HardwareSpaghettiMonster`

Extends `BlindOracle` with custom policies.

[API docs](./HardwareSpaghettiMonster.md)