/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

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

    protected static final byte PIN_MAX_LENGTH           = (byte)32;
    protected static final byte PIN_MAX_COUNTER          = (byte)10;

    protected OwnerPIN pin = null;
    protected DataEntry secretData = null;

    private SECP256k1 secp256k1;
    private RandomData rng;
    private MessageDigest sha256;
    private HMACDigest hmac_sha256;
    private Cipher cipher;
    private KeyAgreement ecdh;

    private KeyPair uniqueKeyPair;
    // private byte[] secret;
    private byte[] sharedSecret;
    private Key sharedKey;
    private byte[] iv;
    private byte[] tempBuffer;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public MemoryCardApplet(){

        // crypto primitives
        secp256k1 = new SECP256k1();
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hmac_sha256 = new HMACDigest(sha256, HMACDigest.ALG_SHA_256_BLOCK_SIZE);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);

        // generate random secret key for secure communication
        uniqueKeyPair = secp256k1.newKeyPair();
        uniqueKeyPair.genKeyPair();
        // fill with rng to make sure at first nobody can talk to the card
        sharedSecret = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        rng.generateData(sharedSecret, (short)0, (short)32);
        iv = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        rng.generateData(iv, (short)0, (short)16);
        // temporary buffer for stuff
        tempBuffer = JCSystem.makeTransientByteArray(MAX_DATA_LENGTH, JCSystem.CLEAR_ON_DESELECT);

        sharedKey = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        ((AESKey)sharedKey).setKey(sharedSecret, (short)0);
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

        JCSystem.requestObjectDeletion();
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
        case INS_PERFORM_ECDH:
            EstablishSharedSecret(apdu);
            break;
        case (byte)0xA4:
            Encrypt(apdu);
            break;
        default:
            // If you don't know the INS, throw an exception.
            // ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            SendHello(apdu);
        }
    }
    protected void Encrypt(APDU apdu){
        byte[] buf = apdu.getBuffer();
        short len = buf[ISO7816.OFFSET_LC];
        rng.generateData(iv, (short)0, (short)16);
        cipher.init(sharedKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)16);
        len = cipher.doFinal(buf, ISO7816.OFFSET_CDATA, len, tempBuffer, (short)0);
        Util.arrayCopyNonAtomic(iv, (short)0, buf, (short)0, (short)16);
        Util.arrayCopyNonAtomic(tempBuffer, (short)0, buf, (short)16, len);
        len += 16;
        hmac_sha256.init(sharedSecret, (short)0, (short)32);
        len += hmac_sha256.doFinal(buf, (short)0, len, buf, len);
        apdu.setOutgoingAndSend((short)0, len);
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
     * Sends unique public key from the card in APDU responce
     * @param apdu the APDU buffer
     */
    protected void SendPubkey(APDU apdu){
        byte[] buf = apdu.getBuffer();
        ECPublicKey pub = (ECPublicKey)uniqueKeyPair.getPublic();
        pub.getW(buf, (short)0);
        apdu.setOutgoingAndSend((short)0, (short)65);
    }
    /**
     * Sends 32 random bytes in APDU responce
     * @param apdu the APDU buffer
     */
    protected void SendRandom(APDU apdu){
        byte[] buf = apdu.getBuffer();
        rng.generateData(buf, (short)0, (short)32);
        apdu.setOutgoingAndSend((short) 0, (short)32);
    }
    protected void EstablishSharedSecret(APDU apdu){
        byte[] buf = apdu.getBuffer();
        // cast signed byte to unsigned short
        short len = buf[ISO7816.OFFSET_LC];
        // check if data length is ok
        if(len != (byte)65){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ecdh.init((ECPrivateKey)uniqueKeyPair.getPrivate());
        ecdh.generateSecret(buf, ISO7816.OFFSET_CDATA, (short)65, sharedSecret, (short)0);
        ((AESKey)sharedKey).setKey(sharedSecret, (short)0);
        // sending sha256 of the shared secret
        sha256.reset();
        sha256.doFinal(sharedSecret, (short)0, (short)32, buf, (short)0);
        apdu.setOutgoingAndSend((short)0, (short)32);
    }
}