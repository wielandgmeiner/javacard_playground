package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: SingleUseKeyApplet.java 
 * Class: SingleUseKeyApplet
 */
public class SingleUseKeyApplet extends SecureApplet{

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    private static final byte CMD_SINGLE_USE_KEY      = (byte)0x20;
    // instructions for plaintext
    private static final byte INS_SINGLE_USE_KEY      = (byte)0xA0;

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
    // ok, if you want to use it without secure communication 
    // - you should be able to, even though it might be an issue with MITM
    // if you don't - comment out this function
    protected short processPlainMessage(byte[] buf, short off, short len){
        // ugly copy-paste for now
        switch (buf[ISO7816.OFFSET_INS]){
            case INS_SINGLE_USE_KEY:
                switch (buf[ISO7816.OFFSET_P1]){
                    case SUBCMD_SINGLE_USE_KEY_GENERATE:
                        generateRandomKey();
                        // no need to break - we return compressed pubkey
                        // but compiler complains, so
                        return Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, (short)0);
                    case SUBCMD_SINGLE_USE_KEY_GET_PUBKEY:
                        // serialize pubkey in compressed form
                        return Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, (short)0);
                    case SUBCMD_SINGLE_USE_KEY_SIGN:
                        len = Secp256k1.sign((ECPrivateKey)singleUseKeyPair.getPrivate(), buf, ISO7816.OFFSET_CDATA, buf, (short)0);
                        // when done - overwrite key with new random values
                        generateRandomKey();
                        return len;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        return (short)0;
    }
    protected short processSecureMessage(byte[] buf, short offset, short len){
        if(buf[offset] == CMD_SINGLE_USE_KEY){
            return processSingleUseKeyCommand(buf, offset, len);
        }else{
            ISOException.throwIt(ERR_INVALID_CMD);
        }
        return (short)2;
    }
    private short processSingleUseKeyCommand(byte[] buf, short offset, short len){
        if(isLocked()){
            ISOException.throwIt(ERR_CARD_LOCKED);
            return (short)2;
        }
        byte subcmd = buf[(short)(offset+1)];
        buf[offset] = (byte)0x90;
        buf[(short)(offset+1)] = (byte)0x00;
        switch (subcmd){
            case SUBCMD_SINGLE_USE_KEY_GENERATE:
                generateRandomKey();
                // no need to break - we return compressed pubkey
                // but compiler complains, so
                return (short)(2+Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, (short)(offset+2)));
            case SUBCMD_SINGLE_USE_KEY_GET_PUBKEY:
                // serialize pubkey in compressed form
                return (short)(2+Secp256k1.serialize((ECPublicKey)singleUseKeyPair.getPublic(), true, buf, (short)(offset+2)));
            case SUBCMD_SINGLE_USE_KEY_SIGN:
                len = Secp256k1.sign((ECPrivateKey)singleUseKeyPair.getPrivate(), buf, (short)(offset+2), buf, (short)(offset+2));
                // when done - overwrite key with new random values
                generateRandomKey();
                return (short)(2+len);
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return (short)2;
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