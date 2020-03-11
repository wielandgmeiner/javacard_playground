// define package name.
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: MemoryCardApplet.java 
 * Class: MemoryCardApplet
 */
public class MemoryCardApplet extends Applet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    protected static final byte CLA_MEMORYCARD            = (byte)0xB0;

    /* Secure channel stuff */
    // Get EC public key for ECDH key agreement
    // Static. Host should compare with a known one
    protected static final byte INS_GET_PUBKEY            = (byte)0xA1;
    // Get 32 random bytes
    protected static final byte INS_GET_RANDOM            = (byte)0xA2;

    // Do ECDH
    protected static final byte INS_PERFORM_ECDH          = (byte)0xA3;

    // Challenge management - to detect swapping of the card
    // We limit number of challenges to avoid sweep
    protected static final byte INS_CHALLENGE_GET_COUNTER = (byte)0x10;
    // does HMAC-SHA256(challenge, challenge_secret) with internal secret
    protected static final byte INS_HMAC_CHALLENGE        = (byte)0x11;

    // PIN management. Not according to ISO 7816-4. Should we care?
    protected final static short SW_WRONG_PIN = (short) 0x63c0;
    // try to unlock with the PIN
    protected static final byte INS_PIN_VERIFY            = (byte)0x20;
    // get PIN counter - returns max counter value and attempts left
    // PIN counter should be decrementing and boundary checked
    // Using built-in OwnerPIN for now.
    protected static final byte INS_PIN_GET_COUNTER       = (byte)0x21;
    // set PIN for uninitialized or change for unlocked card
    protected static final byte INS_PIN_SET               = (byte)0x22;
    // lock the card
    protected static final byte INS_LOCK                  = (byte)0x23;
    // get card status - locked or not
    protected static final byte INS_IS_LOCKED             = (byte)0x24;

    // from TEAPOT class, with CLA_MEMORYCARD available only when unlocked
    // protected static final byte INS_GET                  = (byte)0xA1;
    // protected static final byte INS_PUT                  = (byte)0xA2;

    // Max storage
    protected static final short MAX_DATA_LENGTH         = (short)255;

    protected static final byte PIN_MAX_LENGTH = (byte)32;
    protected static final byte PIN_MAX_COUNTER = (byte)10;

    protected OwnerPIN pin = null;
    protected DataEntry secretData = null;

    private SECP256k1 secp256k1;
    private RandomData rng;
    private byte[] secret;
    private byte[] sharedSecret;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public MemoryCardApplet(){

        secp256k1 = new SECP256k1();
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        secret = new byte[32];
        rng.generateData(secret, (short)0, (short)32);
        // make sure at first nobody can talk to the card
        sharedSecret = new byte[32];
        rng.generateData(sharedSecret, (short)0, (short)32);
        // Default data
        byte[] defaultData = { 
            'M', 'e', 'm', 'o', 'r', 'y', ' ', 'c', 
            'a', 'r', 'd', 's', ' ', 'a', 'r', 'e', 
            ' ', 'n', 'o', 't', ' ', 's', 'a', 'f', 
            'u', ' ', 's', 'o', ' ', 'w', 'h', 'a',
            't', '?'
        };
        if (secretData == null){
            secretData = new DataEntry(MAX_DATA_LENGTH);
        }
        secretData.put(defaultData, (short)0, (short)defaultData.length);
    }
    // Process the command APDU, 
    // All APDUs are received by the JCRE and preprocessed. 
    public void process(APDU apdu){
        // Select the Applet, through the select method, this applet is selectable, 
        // After successful selection, all APDUs are delivered to the currently selected applet
        // via the process method.
        if (selectingApplet()){
            return;
        }
        // Get the APDU buffer byte array.
        byte[] buf = apdu.getBuffer();
        // Calling this method indicates that this APDU has incoming data. 
        apdu.setIncomingAndReceive();
        
        // If the CLA is not equal to 0xB0(CLA_MEMORYCARD),  throw an exception.
        if(buf[ISO7816.OFFSET_CLA] != CLA_MEMORYCARD){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // Dispatch INS in APDU.
        switch (buf[ISO7816.OFFSET_INS]){
        case INS_GET_PUBKEY:
            // The APDU format can be "B0 A1 P1 P2 Lc Data Le", 
            // such as "B0A10000" or "B0A101020311223300".
            SendPubkey(apdu);
            break;
        case INS_GET_RANDOM:
            SendRandom(apdu);
            break;
        default:
            // If you don't know the INS, throw an exception.
            // ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            SendHello(apdu);
        }
    }
    /**
     * Sends data from the card in APDU responce
     * @param apdu the APDU buffer
     */
    protected void SendHello(APDU apdu){
        apdu.setOutgoing();
        apdu.setOutgoingLength(secretData.length());
        apdu.sendBytesLong(secretData.get(), (short)0, secretData.length());
    }
    /**
     * Sends data from the card in APDU responce
     * @param apdu the APDU buffer
     */
    protected void SendPubkey(APDU apdu){
        apdu.setOutgoing();
        byte[] pubOut = new byte[65];
        secp256k1.derivePublicKey(secret, (short)0, pubOut, (short)0);
        apdu.setOutgoingLength((short)65);
        apdu.sendBytesLong(pubOut, (short)0, (short)65);
    }
    protected void SendRandom(APDU apdu){
        apdu.setOutgoing();
        byte[] rand = new byte[32];
        rng.generateData(rand, (short)0, (short)32);
        apdu.setOutgoingLength((short)32);
        apdu.sendBytesLong(rand, (short)0, (short)32);
    }
}