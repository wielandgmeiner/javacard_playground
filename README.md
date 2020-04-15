# JavaCardOS applets

I don't like Java and JavaCardOS, but it is the only way to get some hardware security without NDA. So we have to live with it.

Work in progress, documentation for classes and applets is in the [`doc/`](./doc) folder.

Currently all the applets are tested on [NXP JCOP3 J3H145 card](https://www.smartcardfocus.com/shop/ilp/id~879/nxp-j3h145-dual-interface-java-card-144k/p/index.shtml), but we plan to add support of `Infineon SLE78` and `G&D SmartCafe 7.0` soon.

## Applets

- [`Teapot`](./doc/Teapot.md) - a very simple "Hello world" class that doesn't use any PIN protection or secure communication. It can only store up to `255` bytes of data and give it back on request. Perfect for testing communication with the card.
- [`MemoryCard`](./doc/MemoryCard.md) - adds PIN protection and secure communication.
- [`Calculator`](./doc/Calculator.md) - some ariphmetics on the card - bip32, hmac, inversion, point addition.
- [`BlindOracle`](./doc/BlindOracle.md) - allows bip32 key derivation so the key never leaves the card. Includes nonce blinding protocol to minimize trust in proprietary stuff deployed on the card.
- [`SingleUseKey`](./doc/SingleUseKey.md) - generates a temporary key on the card that can be used only once to sign a single hash. After that the key is deleted. Can be used for proposals like Bob's and Bryan's.
- [`HardwareSpaghettiMonster`](./doc/HardwareSpaghettiMonster.md) - should add custom policies to the card.

For `Teapot` and `MemoryCard` any JavaCard should work. For `BlindOracle` or `HardwareSpaghettiMonster` [NXP J3H145](https://www.smartcardfocus.com/shop/ilp/id~879/nxp-j3h145-dual-interface-java-card-144k/p/index.shtml) should work fine.

# Toolchain installation for Mac

This version of jdk works. The most recent one - not.

Big thanks to https://adoptopenjdk.net/ for all old versions of jdk!

Install deps:

```sh
brew tap adoptopenjdk/openjdk
brew cask install adoptopenjdk/openjdk/adoptopenjdk8
brew install ant@1.9
```

Add to your path (maybe put into `.bash_profile`):

```sh
export PATH="/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/bin/:$PATH"
export PATH="/usr/local/opt/ant@1.9/bin:$PATH"
export JAVA_HOME="/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home"
```

# Tools

- `gp.jar` - a working and easy to use tool for applets management, from https://github.com/martinpaljak/GlobalPlatformPro (LGPL3)
- `ant-javacard.jar` - ant task to build javacard applet, from https://github.com/martinpaljak/ant-javacard (MIT)
- `sdks` folder - JavaCard SDK of different versions (Oracle-owns-you-and-your-grandma license)

Makes sense to make an alias for `gp.jar`:

```sh
alias gp="java -jar $PWD/gp.jar"
```

# How to build

Run to compile all applets:

```sh
ant toys
```

You should get `.cap` files for all the applets in the root folder.

Now upload applet to the card:

```sh
gp -install TeapotApplet.cap
```

Check that it appeared in the list of applets (should appear with aid `B00B5111CA01`):

```sh
gp -l
```

Now you can communicate with the applet.

Jupyter notebook with some examples for applets are in [`jupyter/`](jupyter/) folder.

# Useful links

- https://github.com/OpenCryptoProject/JCMathLib - library for arbitrary elliptic curve operations on javacard
- https://opencryptojc.org/ - making JavaCards open
- https://pyscard.sourceforge.io/ - python tool to talk to smartcards
- https://smartcard-atr.apdu.fr/ - ATR (Answer To Reset) parser
- [keycard.tech](https://keycard.tech/) - JavaCard applet with BIP-32 support
- https://www.youtube.com/watch?v=vd0-Uhx2OoQ - nice talk about JavaCards and open-source ecosystem

# Cards that make sense

Compatibility table: https://www.fi.muni.cz/~xsvenda/jcalgtest/table.html

## Algorithms

`ALG_EC_SVDP_DH_PLAIN` should be there. Many cards support it. Not necessarily `ALG_EC_SVDP_DH_PLAIN_XY`. Required for point multiplication (other than G, i.e. for Schnorr)

`ALG_EC_PACE_GM` is a nice one - allows point addition. AFAIK available only on NXP JCOP3 J3H145 and NXP JCOP4 series.

`TYPE_EC_FP_PRIVATE_TRANSIENT` - useful for bip32 derivation
Infineon SLE78 JCard, G&D Smartcafe 7.0, NXP JCOP4 P71D321, NXP JCOP4 J3R200
Taisys SIMoME Vault

`ALG_HMAC_SHA512` - useful for fast PBKDF2 in BIP-39
Taisys SIMoME Vault

# Don't write your own crypto

But sometimes we have to... 
Here we have modulo addition for bip32 key derivation, this one is critical.
For public key uncompression we can use fast functions as no secrets are involved there.

For finite field ariphmetics we are abusing `RSA` encryption coprocessor where we set modulo to `FP` or `N` of `secp256k1` curve and public key to the exponent we need.

Point addition is implemented using `ALG_EC_PACE_GM`, but can be also done manually with a few simple equations over `FP`.

## Rules for crypto

- No branching - if cases can be detected
- Don't do case-via-offset - access time to elements with different indexes can be different
- Use transient arrays when possible - it's orders of magnitude faster than EEPROM
- Use `Key` class when possible, JC platforms secures them better than simple arrays
- Encrypt-then-hmac is better than anything else
- Use ephimerial keys when possible, they help against replay attacks

# Notes

Key for [keycard.tech](https://keycard.tech/): `c212e073ff8b4bbfaff4de8ab655221f`
