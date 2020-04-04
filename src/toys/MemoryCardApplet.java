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
public class MemoryCardApplet extends TeapotApplet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    private static final byte CLA_MEMORYCARD            = (byte)0xB0;

    // Get 32 random bytes
    private static final byte INS_GET_RANDOM            = (byte)0xB1;

    /* Secure channel stuff */
    // Get EC public key for ECDH key agreement
    // Static. Host should compare with a known one
    private static final byte INS_GET_CARD_PUBKEY       = (byte)0xB2;
    // secret will be ECDH(Card Static, Host Ephimerial)  
    private static final byte INS_SET_HOST_PUBKEY       = (byte)0xB3;
    // secret will be ECDH(Card Ephimerial, Host Ephimerial)
    private static final byte INS_SET_HOST_GET_EPH      = (byte)0xB4;
    private static final byte INS_SECURE_MESSAGE        = (byte)0xB5;
    private static final byte INS_CLOSE_CHANNEL         = (byte)0xB6;

    // Challenge management - to detect swapping of the card
    // We limit number of challenges to avoid sweep
    private static final byte INS_CHALLENGE_GET_COUNTER = (byte)0x10;
    // does HMAC-SHA256(challenge, challenge_secret) with internal secret
    private static final byte INS_HMAC_CHALLENGE        = (byte)0x11;

    // PIN management. Not according to ISO 7816-4. Should we care?
    private final static short SW_WRONG_PIN = (short) 0x63c0;
    // try to unlock with the PIN
    private static final byte INS_PIN_VERIFY            = (byte)0x20;
    // get PIN counter - returns max counter value and attempts left
    // PIN counter should be decrementing and boundary checked
    // Using built-in OwnerPIN for now.
    private static final byte INS_PIN_GET_COUNTER       = (byte)0x21;
    // set PIN for uninitialized or change for unlocked card
    private static final byte INS_PIN_SET               = (byte)0x22;
    // lock the card
    private static final byte INS_LOCK                  = (byte)0x23;
    // get card status - locked or not
    private static final byte INS_IS_LOCKED             = (byte)0x24;

    // Max storage
    private static final short MAX_DATA_LENGTH         = (short)255;

    private static final byte PIN_MAX_LENGTH           = (byte)32;
    private static final byte PIN_MAX_COUNTER          = (byte)10;

    private OwnerPIN pin = null;
    private DataEntry secretData = null;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public MemoryCardApplet(){
        super();

        // Crypto primitives. 
        // Keep it in this order.
        Secp256k1.init();
        Crypto.init();
        SecureChannel.init();

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

        // do I need this?
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
        
        // If the CLA is not equal to 0xB0(CLA_MEMORYCARD),  
        // pass it to parent - maybe it can handle
        if(buf[ISO7816.OFFSET_CLA] != CLA_MEMORYCARD){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // Dispatch INS in APDU.
        switch (buf[ISO7816.OFFSET_INS]){
        case INS_GET_CARD_PUBKEY:
            // The APDU format can be "B0 A1 P1 P2 Lc Data Le", 
            // such as "B0A10000" or "B0A101020311223300".
            sendCardPubkey(apdu);
            break;
        case INS_SET_HOST_PUBKEY:
            // this one uses random key from host and
            // static key from card - simple key agreement
            setHostPubkey(apdu);
            break;
        case INS_SET_HOST_GET_EPH:
            // this one uses random keys from both parties
            // more secure, but probably uses EEPROM :(
            setHostGetEphimerial(apdu);
            break;
        case INS_SECURE_MESSAGE:
            handleSecureMessage(apdu);
            break;
        case INS_GET_RANDOM:
            sendRandom(apdu);
            break;
        default:
            // If we don't know the INS, 
            // pass it to the parent
            super.process(apdu);
        }
    }
    // private void Encrypt(APDU apdu){
    //     byte[] buf = apdu.getBuffer();
    //     apdu.setIncomingAndReceive();

    //     short len = buf[ISO7816.OFFSET_LC];
    //     len = SecureChannel.encrypt(buf, ISO7816.OFFSET_CDATA, len, buf, (short)0);
    //     apdu.setOutgoingAndSend((short)0, len);
    // }
    /**
     * Sends unique public key from the card in APDU responce
     * @param apdu the APDU buffer
     */
    private void sendCardPubkey(APDU apdu){
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        // put static public key of the card to the buffer
        short len = SecureChannel.serializeStaticPubkey(buf, (short)0);
        apdu.setOutgoingAndSend((short)0, len);
    }
    private void setHostPubkey(APDU apdu){
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // cast signed byte to unsigned short
        short len = buf[ISO7816.OFFSET_LC];
        // check if data length is ok
        if(len != (byte)65){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        SecureChannel.establishSharedSecret(buf, ISO7816.OFFSET_CDATA, false);
        // get hash of the shared secret and put it to the buffer
        len = SecureChannel.getSharedHash(buf, (short)0);
        // add hmac using shared secret
        len += SecureChannel.authenticateData(buf, (short)0, len, buf, len);
        // add signature with static pubkey
        len += SecureChannel.signData(buf, (short)0, len, buf, len);
        // send hash of the shared secret, hmac and signature back to the host
        apdu.setOutgoingAndSend((short)0, len);
    }
    private void setHostGetEphimerial(APDU apdu){
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // cast signed byte to unsigned short
        short len = buf[ISO7816.OFFSET_LC];
        // check if data length is ok
        if(len != (byte)65){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        SecureChannel.establishSharedSecret(buf, ISO7816.OFFSET_CDATA, true);
        // get session pubkey and put it to the buffer
        len = SecureChannel.serializeSessionPubkey(buf, (short)0);
        // add hmac using shared secret
        len += SecureChannel.authenticateData(buf, (short)0, len, buf, len);
        // add signature with static pubkey
        len += SecureChannel.signData(buf, (short)0, len, buf, len);
        // send pubkey, hmac and signature back to the host
        apdu.setOutgoingAndSend((short)0, len);
    }
    private void handleSecureMessage(APDU apdu){
        sendRandom(apdu);
    }
    /**
     * Sends 32 random bytes in APDU responce
     * @param apdu the APDU buffer
     */
    private void sendRandom(APDU apdu){
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        // fill buffer with 32 bytes of random data
        Crypto.random.generateData(buf, (short)0, (short)32);
        // send it to the host
        apdu.setOutgoingAndSend((short) 0, (short)32);
    }
}