# `MemoryCard`

Extends `Teapot`, adds PIN protection and secure communication.

Also has a unique secret that can do HMAC-SHA256 for `100` arbitrary messages while locked (without PIN) - it can be used as an tamper countermeasure to make sure that the applet and card is not swapped to a different one.
When card is unlocked this counter is reset back to max value.

PIN length can be anything up to 32 bytes. If your scheme uses longer PINs send `sha256(PIN)` instead.

Maximum secret length: `255` bytes. It is enough to store bip39 recovery phrase (max word length in bip39 is 8 letters, 24 words max + spaces).

*Note* We should reimplement or duplicate the PIN verification mechanism as we don't trust proprietary stuff. Especially because it may be implemented poorly on different card models.

*Note* We should also implement our own secure communication protocol, same reasons.

## APDUs

Applet ID: `B00B5111CB01`

To select applet use `SELECT` APDU: `00A4040006B00B5111CB0100`

[`Teapot` API](./Teapot.md#apdus)