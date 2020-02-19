# `MemoryCard`

Extends `Teapot`, adds PIN protection and secure communication.

Also has a unique secret that can do HMAC-SHA256 for 100 arbitrary messages while locked (without PIN) - it can be used as an tamper countermeasure to make sure that the applet and card is not swapped to a different one.

Maximum secret length: `255` bytes. It is enough to store bip39 recovery phrase (max word length in bip39 is 8 letters, 24 words max + spaces).

## APDUs

Applet ID: `B00B5111CA02`

To select applet use `SELECT` APDU: `00A4040006B00B5111CA0200`

[`Teapot` API](./Teapot.md#apdus)