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

Extends [`Teapot` API](./Teapot.md#apdus)

### Unsecure Get Random

Returns 32 random bytes

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB1`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: 32 random bytes |

Example: `B0B1000000` -> returns 32 random bytes

### Get card's static public key

This key is generated when the applet is installed. It will remain the same whenever you insert the card, but when applet is updated it will be re-generated.

Once you know the card's static public key you can use it to establish secure communication channel. You can also verify that the card is the same next time you start talking to it.

This APDU returns 65-byte sequence with serialized uncompressed public key (`0x04<x><y>`)

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB2`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: 65 bytes with serialized static pubkey |

Example: `B0B2000000` -> returns 65 bytes with static public key of the card, for example `045879312CB80C51B6FF53EF946603E64CCA37C9E06D96E7FB7BB798F822117D89FB537A4F53EA59802946AB4532BCD403EFA20518360411C262C010B1A496B39C`.

### Establish secure channel

For secure communication we need to establish shared secrets. For this we use ECDH key agreement. We use `AES_CBC` for encryption with `M2` padding (add `0x8000..00` to round to 16-byte blocks). HMAC-SHA256 is used for authentication and applied to the ciphertext (encrypt-then-hmac).

There are 3 different modes you can use - `ss`, `es` and `ee`.
- In `ss` mode both card and host use static public keys and 32-byte random nonces. Shared secret is derived as `sha256(ecdh(s,s) | host_nonce | card_nonce)`.
- In `es` mode the host uses a random key, card uses a static key and a random nonce. Shared secret is derived as `sha256(ecdh(e,s) | card_nonce)`.
- In `ee` mode both use random keys, secret is calculated as `sha256(ecdh(e,e))`.

This shared secret is used to derive 4 keys for encryption and authentication for each side:

- `host_aes_key=SHA256('host_aes'|secret)` - symmetric key for data from the host
- `card_aes_key=SHA256('card_eas'|secret)` - symmetric key for data coming from the card
- `host_mac_key=SHA256('host_mac'|secret)` - authentication key for data from the host
- `card_mac_key=SHA256('card_mac'|secret)` - authentication key for data coming from the card

When secure channel is established `iv` for the `AES` cypher is set to `0` and incremented on every message. We can use the same `iv` both for incoming and outgoing data because we use different keys on each side. `iv` is not transmitted but is used in `hmac` authentication.

If you are out of sync for some reason just re-establish secure channel. If `iv` is hitting the limit of 16 bytes - also re-establish secure channel.

### Establish secure channel in SS mode

Returns `< 32-byte card nonce > | HMAC-SHA256(card_key, data) | ECDSA_SIGNATURE`.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB3`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | 65-byte public key of the host serialized in uncompressed form followed by the 32-byte host nonce |
| RETURN | `SW`: `0x9000`, `DATA`: `< 32-byte card nonce > | HMAC-SHA256(card_key, data) | ECDSA_SIGNATURE`  |

### Establish secure channel in ES mode

Returns `< 32-byte card nonce > | HMAC-SHA256(card_key, data) | ECDSA_SIGNATURE`.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB4`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | 65-byte public key of the host serialized in uncompressed form |
| RETURN | `SW`: `0x9000`, `DATA`: `< 32-byte card nonce > | HMAC-SHA256(card_key, data) | ECDSA_SIGNATURE` |

### Establish secure channel in EE mode

Returns `< card ephemeral pubkey > | HMAC-SHA256(card_key, data) | ECDSA_SIG(card_pubkey, data incl HMAC)`.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB5`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | 65-byte public key of the host serialized in uncompressed form |
| RETURN | `SW`: `0x9000`, `DATA`: 65-byte cards fresh pubkey followed by `HMAC-SHA256(card_key, data)`, then ECDSA signature signing all previous data |

### Secure message

All commands via secure channel are sent with this APDU. If decryption or authentication check failed the card will throw an error and close the channel. Otherwise it will always return `0x9000`, but inside the payload it will send the actual data or error code.

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB6`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | encrypted payload                        |
| RETURN | `SW`: `0x9000`, `DATA`: encrypted responce |

Maximum size of the encrypted payload is `255` bytes. Even though we could use extended APDU, but we don't really need this. We have very strict RAM limits anyways, so we can always work with 255 bytes or less.

Message is formed as follows:
- All messages coming from the host should be encrypted using `host_aes_key` and authenticated with `host_mac_key`
- All responces from card are encrypted with `card_aes_key` and authenticated with `card_mac_key`
- `AES-CBC` with `M2` padding (`0x8000...00`) is used to round data to 16-byte AES blocks.
- For authentication we use first `15` bytes of `HMAC-SHA256(key, iv | ciphertext)`
- You need to increase `iv` after every request to the card.

Encrypted packet format: `< ciphertext > < hmac_sha256(key, iv|ciphertext)[:15] >`

### Close channel

Closes secure communication channel. Internally overwrites all session keys with random junk, so nobody will be able to communicate with the card. I have no idea what's the reason to do that...

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xB7`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: empty            |

## SC commands

We encode data in secure message in the following form:

```
payload: <2-byte command><data>
```

Responce coming from the card has the structure:

```
response: <2-byte status code><data>
```

In total payload should be at most `223` bytes, otherwise it will not fit in a single packet. So data part is limited to `221` byte. It should be enough even for the largest possible mnemonic phrase that is `24*9-1 = 215` bytes.

Success status code is `0x9000`, just to be consistent. All error codes are... different, just because fuck this stupid closed-source approach where you need to pay 100 bucks to get full specification.

Commands marked with `PIN protected` can be used only if the card is unlocked.

TODO Commands:

- Echo: `0x0000<data>` - good for testing. Returns the same data back.
- Get random number: `0x0100` - returns 32 random bytes
- Anti-phishing commands: `0x02<code>` - counter increased with every request, but only if card is locked. Can be used for card authentication by the user (double PIN approach of ColdCard or anti-phishing words in Specter)
  - Get counter: `0x0200` - returns `<signatures_left><signatures_max=100>`
  - Signature mode: `0x0201<msg:32>` - returns ECDSA signature of `"auth"|data`
  - HMAC mode: `0x0202<msg:32>` - returns HMAC-SHA256 with `"auth"|data`
- PIN commands: `0x03<code>`
  - Get status: `0x0300` -> `<attempts_left><attempts_max=10><status>`
  - Unlock: `0x0301<pin:max32>` `<pin>` -> ok (`0x9000`), wrong pin, permanently locked. If PIN is not initialized and you try to unlock it - pin will set to provided value.
  - Lock: `0x0302`
  - Change PIN: `0x0303<len_old><old_pin><len_new><new_pin>` - PIN protected
- Wipe: `0x0400`
- Data storage: `0x05<code>` - PIN protected
  - Get data: `0x0500`
  - Put data: `0x0501<data>` - max `221` bytes

TODO Status codes:
- pin
  - pin not set
  - wrong pin
  - permanently locked
- invalid data ???
- invalid length (i.e. when you try to set PIN larger than 32 bytes)
