# `Teapot`

A very simple "Hello world" class that doesn't use any PIN protection or secure communication. It can only store up to 64 bytes of data and give it back on request. Perfect for testing communication with the card.

By default the phrase is `I am a teapot gimme some tea plz`.

Maximum storage size - `64` bytes.

## APDUs

Applet ID: `B00B5111CA01`

To select applet use `SELECT` APDU: `00A4040006B00B5111CA0100`

### Get secret

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xA1`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | ignored                                  |
| RETURN | `SW`: `0x9000`, `DATA`: data stored in the card |

Example: `B0A100000000` -> returns stored data

### Store secret

| Field  | Value                                    |
| ------ | ---------------------------------------- |
| CLA    | `0xB0`                                   |
| INS    | `0xA2`                                   |
| P0, P1 | ignored, use for example `0x00` for both |
| DATA   | data to store on the card, `64` bytes max  |
| RETURN | `SW`: `0x9000`, `DATA`: updated data stored on the card |
| ERRORS | `SW`: `0x6700` (`ISO7816.SW_WRONG_LENGTH`) if data is more than `64` bytes |

Example: `B0A20000<len><data>00`

- Data: `shiny teapot taking care of your secrets`
- Data in hex: `7368696e7920746561706f742074616b696e672063617265206f6620796f75722073656372657473`
- Data length: 40 (`0x28`)
- APDU: `B0A20000287368696e7920746561706f742074616b696e672063617265206f6620796f7572207365637265747300`
