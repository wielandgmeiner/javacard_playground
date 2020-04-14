/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/* 
 * Package: toys
 * Filename: SingleUseKeyApplet.java 
 * Class: SingleUseKeyApplet
 */
public class SingleUseKeyApplet extends SecureApplet{

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    private static final byte CMD_SINGLE_USE_KEY      = (byte)0x20;

    /************ key management *********/

    // generates a new random key
    // can be used for signing only once
    private static final byte SUBCMD_SINGLE_USE_KEY_GENERATE   = (byte)0x00;
    // get corresponding public key
    // use this key to construct the transaction
    private static final byte SUBCMD_SINGLE_USE_KEY_GET_PUBKEY = (byte)0x01;
    // sign hash with private key
    // instantly deletes the key after usage
    private static final byte SUBCMD_SINGLE_USE_KEY_SIGN       = (byte)0x02;


    private ECPrivateKey singleUseKey;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new SingleUseKeyApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public SingleUseKeyApplet(){
        super();
        singleUseKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    }
    protected short processSecureMessage(byte[] buf, short offset, short len){
        return sendError(ERR_INVALID_CMD, buf, offset);
    }
    protected short processPlainMessage(byte[] msg, short msgOff, short msgLen){
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return (short)0;
    }
}