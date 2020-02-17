# JavaCardOS applets

I hate Java and JavaCardOS, but it is the only way to get some hardware security without NDA. So we have to live with it.

Work in progress, this is a description of what it should look like at the end:

## `Teapot`

Stores a phrase `I am a teapot gimme some tea plz` or any other 32-byte secret you want to store.
No PIN, no authentication - just stores a 32-byte sequence.

## `MemoryCard`

Extends `Teapot`, adds PIN protection and secure communication

## `BlindOracle`

Extends `MemoryCard`.
Adds another slot for a 64-byte key that is write-only - you can load a key to this slot or generate one on the card, and then use bip-32 to derive new keys, and sign arbitrary messages.
Curve - `secp256k1`, signature - `ECDSA`.

## HardwareSpaghettiMonster

Extends `BlindOracle` with custom policies.

# Toolchain installation for Mac

This version of jdk works. The most recent one - not.

Big thanks to https://adoptopenjdk.net/ for all old versions of jdk!

```sh
brew tap adoptopenjdk/openjdk
brew cask install adoptopenjdk/openjdk/adoptopenjdk8
brew install ant@1.9
```

Add to your path:

```sh
export PATH="/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/bin/:$PATH"
export PATH="/usr/local/opt/ant@1.9/bin:$PATH"
export JAVA_HOME="/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home"
```

# Tools

- `gp.jar` - a working and easy to use tool for applets management, from https://github.com/martinpaljak/GlobalPlatformPro (LGPL3)
- `ant-javacard.jar` - ant task to build javacard applet, from https://github.com/martinpaljak/ant-javacard (MIT)
- `ext` folder - JavaCard SDK of different versions (Oracle-owns-you-and-your-grandma license)

Makes sense to make an alias for `gp.jar`:

```sh
alias gp="java -jar $PWD/gp.jar"
```

# How to build

Run:

```sh
ant sextoys
```

You should get `.cap` files for all the applets in the root folder.

Now upload applet to the card:

```sh
gp -install <applet_name>.cap
```

Check that it appeared in the list of applets:

```sh
gp -l
```

Now you can communicate with the applet.

Jupyter notebook with some examples - `comm.ipynb`.

# Useful links

- https://github.com/OpenCryptoProject/JCMathLib - library for arbitrary elliptic curve operations on javacard
- https://opencryptojc.org/ - making JavaCards open
- https://pyscard.sourceforge.io/ - python tool to talk to smartcards
- https://smartcard-atr.apdu.fr/ - ATR (Answer To Reset) parser
- [keycard.tech](https://keycard.tech/) - JavaCard applet with BIP-32 support
- https://www.youtube.com/watch?v=vd0-Uhx2OoQ - nice talk about JavaCards and open-source ecosystem

# Notes

Key for [keycard.tech](https://keycard.tech/): c212e073ff8b4bbfaff4de8ab655221f

# ToDo

- secure communication protocol (auth-enc)
- store 32-byte secret(s)
- set 32-byte "pin code" (tagged_hash("CardUnlock", device_secret || pin_code))
- get 32-byte secret(s)
- get status - uninitialized, unlocked, locked, permanently locked
- get pin counter <current_counter><max_counter>
- anti-tamper challenge -> 32-byte challenge -> sign with secret -> ecdsa signature
- anti-tamper counter
