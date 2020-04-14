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
    private static final byte CMD_BIP32               = (byte)0x11;

    /************ seed management *********/

    // set seed and mnemonic. seed is 64 bytes, 
    // mnemonic - either full mnemonic or just sha512(mnemonic)
    // (it's the same, card doesn't verify mnemonic anyways)
    private static final byte SUBCMD_SEED_SET_SEED_AND_MNEMONIC = (byte)0x00;
    // set mnemonic only
    private static final byte SUBCMD_SEED_SET_MNEMONIC          = (byte)0x01;
    // derive default seed from mnemonic with empty password
    // WARNING: takes a long time, ~70 seconds!!!
    private static final byte SUBCMD_SEED_CALCULATE_DEFAULT     = (byte)0x02;
    // derive a seed from mnemonic and password
    // card will forget password after derivation
    // and will forget seed after deselect / reset
    private static final byte SUBCMD_SEED_DERIVE_WITH_PASSWD    = (byte)0x03;
    // generate random "mnemonic" and seed
    // WARNING: doesn't return the seed, so it always stays only on this card
    //          add some backup mechanism in a script to recover if card breaks
    // As seed is never backed up we don't use pbkdf2 here
    // We use a simple way to calculate seed: seed=hmac(mnemonic, passphrase)
    // Then you don't need to wait for 1 minute and still can use passwords
    private static final byte SUBCMD_SEED_GEN_RANDOM_SEED       = (byte)0x7D;

    /************ master private key management *********/

    // first use SUBCMD_SEED_DERIVE_WITH_PASSWD to get master private key
    // returns 4-byte fingerprint (hash160(pubkey)[:4])
    private static final byte SUBCMD_BIP32_GET_FINGERPRINT       = (byte)0x00;
    // pass array of 4-byte indexes for derivation path
    // max derivation len is ~50, should be enough for everyone
    // sets result to temporary storage, so you can use it for 
    // faster signing afterwards
    private static final byte SUBCMD_BIP32_GET_XPUB              = (byte)0x01;
    // pass 32-byte hash to sign, then fingerprint of the xpub 
    // and array of 4-byte indexes to derive the key
    // If fingerprint is root fingerprint - it will derive key from root
    // If fingerprint is temp bip32 key fingerprint - it will derive from there
    // Otherwise will return errorcode
    private static final byte SUBCMD_BIP32_DERIVE_AND_SIGN       = (byte)0x02;


    private DataEntry mnemonic;

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

        if (secretData == null){
            secretData = new DataEntry(MAX_DATA_LENGTH);
        }
        secretData.put(defaultData, (short)0, (short)defaultData.length);
    }
    protected short processSecureMessage(byte[] buf, short offset, short len){
        return sendError(ERR_INVALID_CMD, buf, offset);
    }
    protected short processPlainMessage(byte[] msg, short msgOff, short msgLen){
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return (short)0;
    }
}