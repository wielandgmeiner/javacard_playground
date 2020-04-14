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

    private KeyPair singleUseKeyPair;
    private byte[] tempBuf;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new SingleUseKeyApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }
    public SingleUseKeyApplet(){
        super();
        tempBuf = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
        singleUseKeyPair = Secp256k1.newKeyPair();
        generateRandomKey();
    }
    protected short processPlainMessage(byte[] buf, short off, short len){
        // ok, if you want to use it without secure communication 
        // - you should be able to
        // TODO: implement message handling without secure channel
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return (short)0;
    }
    protected short processSecureMessage(byte[] buf, short offset, short len){
        if(buf[offset] == CMD_SINGLE_USE_KEY){
            return processSingleUseKeyCommand(buf, offset, len);
        }else{
            return sendError(ERR_INVALID_CMD, buf, offset);
        }
    }
    private short processSingleUseKeyCommand(byte[] buf, short offset, short len){
        if(isLocked()){
            return sendError(ERR_CARD_LOCKED, buf, offset);
        }
        byte subcmd = buf[(short)(offset+1)];
        buf[offset] = (byte)0x90;
        buf[(short)(offset+1)] = (byte)0x00;
        switch (subcmd){
            case SUBCMD_SINGLE_USE_KEY_GENERATE:
                generateRandomKey();
                // no need to break - we return compressed pubkey
                // but compiler complains, so
                return (short)(2+Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, (short)2));
            case SUBCMD_SINGLE_USE_KEY_GET_PUBKEY:
                // serialize pubkey in compressed form
                return (short)(2+Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, (short)2));
            case SUBCMD_SINGLE_USE_KEY_SIGN:
                len = Secp256k1.sign((ECPrivateKey)singleUseKeyPair.getPrivate(), buf, (short)2, buf, (short)2);
                // when done - overwrite key with new random values
                generateRandomKey();
                return (short)(2+len);
            default:
                return sendError(ERR_INVALID_SUBCMD, buf, offset);
        }
    }
    private void generateRandomKey(){
        Secp256k1.generateRandomSecret(tempBuf, (short)0);
        ECPrivateKey prv = (ECPrivateKey)singleUseKeyPair.getPrivate();
        prv.setS(tempBuf, (short)0, (short)32);
        ECPublicKey pub = (ECPublicKey)singleUseKeyPair.getPublic();
        Secp256k1.pointMultiply(prv,
                                Secp256k1.SECP256K1_G, (short)0, (short)65,
                                tempBuf, (short)0);
        pub.setW(tempBuf, (short)0, (short)65);
    }
}