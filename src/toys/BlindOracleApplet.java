/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/* 
 * Package: toys
 * Filename: BlindOracleApplet.java 
 * Class: BlindOracleApplet
 */
public class BlindOracleApplet extends SecureApplet{

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    // seed & mnemonic management
    private static final byte CMD_SEED                = (byte)0x10;
    // bip32 keys
    private static final byte CMD_BIP32               = (byte)0x11;

    /************ seed management *********/

    // set seed and mnemonic. seed is 64 bytes, 
    // mnemonic - either full mnemonic or just sha512(mnemonic)
    // (it's the same, card doesn't verify mnemonic checksum anyways)
    // data format: <64 bytes seed><mnemonic or sha512(mnemonic)>
    private static final byte SUBCMD_SEED_SET_SEED_AND_MNEMONIC  = (byte)0x00;
    // set mnemonic only
    // data format: <mnemonic or sha512(mnemonic)>
    private static final byte SUBCMD_SEED_SET_MNEMONIC           = (byte)0x01;
    // set default seed only
    // can be used for example when mnemonic + seed don't fit
    // in a single message
    // data format: <64-byte seed>
    private static final byte SUBCMD_SEED_SET_DEFAULT_SEED       = (byte)0x02;
    // derive default seed from mnemonic with empty password
    // WARNING: takes a long time, ~70 seconds!!!
    // data: ignored
    private static final byte SUBCMD_SEED_CALCULATE_DEFAULT_SEED = (byte)0x03;
    // derive a seed from mnemonic and password
    // card will forget password after derivation
    // and will forget seed after deselect / reset
    // data: <bip39 password>
    private static final byte SUBCMD_SEED_DERIVE_WITH_PASSWD     = (byte)0x04;
    // generate random "mnemonic" and seed
    // WARNING: doesn't return the seed, so it always stays only on this card
    //          add some backup mechanism in a script to recover if card breaks
    // As seed is never backed up we don't use pbkdf2 here
    // We use a simple way to calculate seed: seed=hmac(mnemonic, passphrase)
    // Then you don't need to wait for 1 minute and still can use passwords
    // data: ignored
    private static final byte SUBCMD_SEED_GEN_RANDOM             = (byte)0x7D;

    /************ master private key management *********/

    // first use SUBCMD_SEED_DERIVE_WITH_PASSWD to get master private key
    // returns 4-byte fingerprint (hash160(pubkey)[:4])
    // data: ignored
    private static final byte SUBCMD_BIP32_GET_FINGERPRINT       = (byte)0x00;
    // pass array of 4-byte indexes for derivation path
    // max derivation len is ~50, should be enough in most cases
    // sets result to temporary storage, so you can use it for 
    // faster signing afterwards
    // data: <4-byte index><4-byte index>...<4-byte index>
    // can be empty - then root xpub will be returned
    private static final byte SUBCMD_BIP32_GET_XPUB              = (byte)0x01;
    // pass 32-byte hash to sign, then fingerprint of the xpub 
    // and array of 4-byte indexes to derive the key
    // If fingerprint is root fingerprint - it will derive key from root
    // If fingerprint is temp bip32 key fingerprint - it will derive from there
    // Otherwise will return errorcode
    // data: <32-byte message hash><4-byte fingerprint><4-byte index>...<4-byte index>
    private static final byte SUBCMD_BIP32_DERIVE_AND_SIGN       = (byte)0x02;

    // 8*24+23 - max 24 words at most 8 characters each + spaces
    private static final short MAX_MNEMONIC_LENGTH               = (short)215;
    private static final short XPUB_LEN                          = (short)78;

    private DataEntry mnemonic;
    private byte[] defaultSeed; // seed with empty password
    private byte[] derivedSeed; // derived seed with provided password, transient
    // options how the key is managed
    private boolean mnemonicIsSet = false;
    private boolean defaultSeedIsSet = false;
    private boolean randomSeedIsUsed = false;
    // root key
    private ECPrivateKey rootPrv;
    private byte[] rootXpub; // 78 bytes
    // child key
    private ECPrivateKey childPrv;
    private byte[] childXpub; // depth, child index, parent fingerprint, chain code, pubkey

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new BlindOracleApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public BlindOracleApplet(){
        super();

        // generate random mnemonic - because why not?
        short len = (short)32;
        short off = heap.allocate(len);

        mnemonic = new DataEntry(MAX_MNEMONIC_LENGTH);
        defaultSeed = new byte[(short)64];
        derivedSeed = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);

        rootPrv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(rootPrv);
        rootXpub = JCSystem.makeTransientByteArray(XPUB_LEN, JCSystem.CLEAR_ON_DESELECT);

        childPrv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(childPrv);
        childXpub = JCSystem.makeTransientByteArray(XPUB_LEN, JCSystem.CLEAR_ON_DESELECT);
    }
    protected short processSecureMessage(byte[] buf, short offset, short len){
        return sendError(ERR_INVALID_CMD, buf, offset);
    }
    protected short processPlainMessage(byte[] msg, short msgOff, short msgLen){
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return (short)0;
    }
}