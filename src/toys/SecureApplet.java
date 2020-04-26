/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/* 
 * Package: toys
 * Filename: SecureApplet.java 
 * Class: SecureApplet
 */
public class SecureApplet extends Applet{

    /*
     * Plaintext instruction codes INS from 0xB1 to 0xB6 are reserved
     * Encrypted command codes     CMD from 0x00 to 0x04 are reserved
     * see below what they do
     *
     * In your applet define functions:
     * - processSecureMessage
     * - processPlainMessage
     *
     * TODO: how to handle constructor?
     * TODO: postUnlock(PIN) method override
     * TODO: postChangePIN(oldPIN, newPIN) method override
     * TODO: postLock()
     */

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

    private static final byte PIN_MAX_LENGTH           = (byte)32;
    private static final byte PIN_MAX_COUNTER          = (byte)10;

    // commands transmitted over secure channel
    private static final byte CMD_ECHO                = (byte)0x00;
    private static final byte CMD_RAND                = (byte)0x01;
    private static final byte CMD_PHISH               = (byte)0x02;
    private static final byte CMD_PIN                 = (byte)0x03;
    private static final byte CMD_WIPE                = (byte)0x04;
    // TODO: reestablish cahnnel without PIN lock
    // private static final byte CMD_REESTABLISH_SC      = (byte)0x06;

    protected static final byte SUBCMD_DEFAULT          = (byte)0x00;
    // pin
    private static final byte SUBCMD_PIN_STATUS       = (byte)0x00;
    private static final byte SUBCMD_PIN_UNLOCK       = (byte)0x01;
    private static final byte SUBCMD_PIN_LOCK         = (byte)0x02;
    private static final byte SUBCMD_PIN_CHANGE       = (byte)0x03;

    // status
    protected static final byte STATUS_PIN_NOT_SET      = (byte)0x00;
    protected static final byte STATUS_CARD_LOCKED      = (byte)0x01;
    protected static final byte STATUS_CARD_UNLOCKED    = (byte)0x02;
    protected static final byte STATUS_CARD_BRICKED     = (byte)0x03;

    // errorcodes
    protected static final short ERR_INVALID_LEN        = (short)0x0403;
    protected static final short ERR_INVALID_CMD        = (short)0x0404;
    protected static final short ERR_INVALID_SUBCMD     = (short)0x0405;
    protected static final short ERR_NOT_IMPLEMENTED    = (short)0x0406;
    protected static final short ERR_CARD_LOCKED        = (short)0x0501;
    protected static final short ERR_INVALID_PIN        = (short)0x0502;
    protected static final short ERR_NO_ATTEMPTS_LEFT   = (short)0x0503;
    protected static final short ERR_ALREADY_UNLOCKED   = (short)0x0504;
    protected static final short ERR_NOT_INITIALIZED    = (short)0x0505;
    protected static final short RESPONSE_SUCCESS       = (short)0x9000;

    private OwnerPIN pin;
    // mb better to do via GP somehow?
    private boolean pinIsSet = false;

    protected TransientHeap heap;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new SecureApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public SecureApplet(){

        heap = new TransientHeap((short)1024);
        // Crypto primitives. 
        // Keep it in this order.
        FiniteField.init(heap);
        Secp256k1.init(heap);
        Crypto.init(heap);
        SecureChannel.init(heap);

        pin = new OwnerPIN(PIN_MAX_COUNTER, PIN_MAX_LENGTH);
    }
    // redefine this function in your applet to process secure message
    // return number of bytes written in the buffer
    // you can write starting from offset 0
    protected short processSecureMessage(byte[] buf, short offset, short len){
        return sendError(ERR_INVALID_CMD, buf, offset);
    }
    // redefine this function in your applet to handle plaintext message
    // return number of bytes written in the buffer
    // you can write starting from offset 0
    // WARNING: no secure channel means MITM attack possibility
    protected short processPlainMessage(byte[] msg, short msgOff, short msgLen){
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return 0;
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
        // Receive incoming data
        // might be limited by the apdu buffer
        // but should work fine with messages up to 255 bytes
        // TODO: refactor for extended length APDUs
        byte[] buf = apdu.getBuffer();
        short dataLen = apdu.getIncomingLength();
        short dataOff = ISO7816.OFFSET_CDATA;
        apdu.setIncomingAndReceive();

        short len = 0;
        // Dispatch INS in APDU.
        switch (buf[ISO7816.OFFSET_INS]){
        case INS_GET_CARD_PUBKEY:
            // The APDU format can be "B0 A1 P1 P2 Lc Data Le", 
            // such as "B0A10000" or "B0A101020311223300".
            len = sendCardPubkey(buf, dataOff, dataLen);
            break;
        case INS_SET_HOST_PUBKEY:
            // this one uses random key from host and
            // static key from card - simple key agreement

            // first - lock the card to avoid active MITM
            if(pinIsSet && pin.isValidated()){
                pin.reset();
            }
            len = setHostPubkey(buf, dataOff, dataLen);
            break;
        case INS_SET_HOST_GET_EPH:
            // this one uses random keys from both parties
            // more secure, but probably uses EEPROM :(

            // first - lock the card to avoid active MITM
            if(pinIsSet && pin.isValidated()){
                pin.reset();
            }
            len = setHostGetEphimerial(buf, dataOff, dataLen);
            break;
        case INS_SECURE_MESSAGE:
            len = handleSecureMessage(buf, dataOff, dataLen);
            break;
        case INS_GET_RANDOM:
            len = sendRandom(buf, dataOff, dataLen);
            break;
        case INS_CLOSE_CHANNEL:
            SecureChannel.closeChannel();
            break;
        default:
            len = processPlainMessage(buf, dataOff, dataLen);
        }
        apdu.setOutgoingAndSend((short)0, len);
    }
    /**
     * Puts unique public key of the card to the message buffer
     */
    private short sendCardPubkey(byte[] msg, short msgOff, short msgLen){
        return SecureChannel.serializeStaticPubkey(msg, (short)0);
    }
    private short setHostPubkey(byte[] msg, short msgOff, short msgLen){
        // check if data length is ok
        if(msgLen != (short)97){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // will put nonce there
        short len = SecureChannel.establishSharedSecret(msg, msgOff, false, msg, (short)0);
        // get hash of the shared secret and put it to the buffer
        len += SecureChannel.getSharedHash(msg, len);
        // add hmac using shared secret
        len += SecureChannel.authenticateData(msg, (short)0, len, msg, len);
        // add signature with static pubkey
        len += SecureChannel.signData(msg, (short)0, len, msg, len);
        return len;
    }
    private short setHostGetEphimerial(byte[] msg, short msgOff, short msgLen){
        // check if data length is ok
        if(msgLen != (byte)65){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // for consistency with se mode
        SecureChannel.establishSharedSecret(msg, msgOff, true, msg, (short)0);
        // get session pubkey and put it to the buffer
        short len = SecureChannel.serializeSessionPubkey(msg, (short)0);
        // add hmac using shared secret
        len += SecureChannel.authenticateData(msg, (short)0, len, msg, len);
        // add signature with static pubkey
        len += SecureChannel.signData(msg, (short)0, len, msg, len);
        return len;
    }
    private short handleSecureMessage(byte[] msg, short msgOff, short msgLen){
        short len = SecureChannel.decryptMessage(msg, msgOff, msgLen, msg, (short)0);
        // processes message and returns len of the responce to send back to host
        // responce is placed back to the same buffer
        len = preprocessSecureMessage(msg, (short)0, len);
        // return len;
        // encrypt buffer and send to the host
        return SecureChannel.encryptMessage(msg, (short)0, len, msg, (short)0);
    }
    private short preprocessSecureMessage(byte[] buf, short offset, short len){
        if(len < 2){
            return sendError(ERR_INVALID_LEN, buf, offset);
        }
        switch (buf[offset]){
            case CMD_ECHO:
                if(buf[(short)(offset+1)] == SUBCMD_DEFAULT){
                    return sendEcho(buf, offset, len);
                }else{
                    return sendError(ERR_INVALID_SUBCMD, buf, offset);
                }
            case CMD_RAND:
                if(buf[(short)(offset+1)] == SUBCMD_DEFAULT){
                    return sendSecRand(buf, offset, len);
                }else{
                    return sendError(ERR_INVALID_SUBCMD, buf, offset);
                }
            case CMD_PIN:
                return processPinCommand(buf, offset, len);
            default:
                return processSecureMessage(buf, offset, len);
        }
    }
    protected short sendError(short errorcode, byte[] buf, short offset){
        Util.setShort(buf, offset, errorcode);
        return 2;
    }
    private short sendEcho(byte[] buf, short offset, short len){
        Util.setShort(buf, offset, RESPONSE_SUCCESS);
        return len;
    }
    private short sendSecRand(byte[] buf, short offset, short len){
        Util.setShort(buf, offset, RESPONSE_SUCCESS);
        Crypto.random.generateData(buf, (short)2, (short)32);
        return (short)34;
    }
    private short processPinCommand(byte[] buf, short offset, short len){
        byte subcmd = buf[(short)(offset+1)];
        Util.setShort(buf, offset, RESPONSE_SUCCESS);
        switch (subcmd){
            case SUBCMD_PIN_STATUS:
                return (short)(2+getPinStatus(buf, (short)(offset+2)));
            case SUBCMD_PIN_UNLOCK:
                if(pinIsSet){
                    if(!pin.isValidated()){
                        if(len > (short)(PIN_MAX_LENGTH+2)){
                            return sendError(ERR_INVALID_LEN, buf, offset);
                        }
                        if(pin.getTriesRemaining() == 0){
                            return sendError(ERR_NO_ATTEMPTS_LEFT, buf, offset);
                        }
                        if(!pin.check(buf, (short)(offset+2), (byte)(len-2))){
                            return sendError(ERR_INVALID_PIN, buf, offset);
                        }
                    }else{
                        return sendError(ERR_ALREADY_UNLOCKED, buf, offset);
                    }
                }else{
                    if(len > (short)(PIN_MAX_LENGTH+2)){
                        return sendError(ERR_INVALID_LEN, buf, offset);
                    }
                    // TODO: wrap in transaction
                    pin.update(buf, (short)(offset+2), (byte)(len-2));
                    pinIsSet = true;
                }
                return (short)2;
            case SUBCMD_PIN_LOCK:
                if(pin.isValidated()){
                    pin.reset();
                }else{
                    // already locked
                    return sendError(ERR_CARD_LOCKED, buf, offset);
                }
                return (short)2;
            case SUBCMD_PIN_CHANGE:
                // check data lengths
                if(len < (short)4){
                    return sendError(ERR_INVALID_LEN, buf, offset);
                }
                short len_old = Util.makeShort((byte)0, buf[(short)(offset+2)]);
                if(len_old > (short)PIN_MAX_LENGTH){
                    return sendError(ERR_INVALID_LEN, buf, offset);
                }
                if(len < (short)(4+len_old)){
                    return sendError(ERR_INVALID_LEN, buf, offset);
                }
                short len_new = Util.makeShort((byte)0, buf[(short)(offset+3+len_old)]);
                if(len_new > (short)PIN_MAX_LENGTH){
                    return sendError(ERR_INVALID_LEN, buf, offset);
                }
                if(len != (short)(4+len_old+len_new)){
                    return sendError(ERR_INVALID_LEN, buf, offset);
                }

                if(!pinIsSet){
                    return sendError(ERR_NOT_INITIALIZED, buf, offset);
                }
                if(!pin.isValidated()){
                    return sendError(ERR_CARD_LOCKED, buf, offset);
                }
                if(!pin.check(buf, (short)(offset+3), (byte)len_old)){
                    return sendError(ERR_INVALID_PIN, buf, offset);
                }else{
                    pin.update(buf, (short)(offset+4+len_old), buf[(short)(offset+3+len_old)]);
                }
                return (short)2;
            default:
                return sendError(ERR_INVALID_SUBCMD, buf, offset);
        }
    }
    private short getPinStatus(byte[] buf, short offset){
        if(!pinIsSet){
            buf[offset] = PIN_MAX_COUNTER;
            buf[(short)(offset+1)] = PIN_MAX_COUNTER;
            buf[(short)(offset+2)] = STATUS_PIN_NOT_SET;
        }else{
            buf[offset] = pin.getTriesRemaining();
            buf[(short)(offset+1)] = PIN_MAX_COUNTER;
            if(pin.getTriesRemaining() == 0){
                buf[(short)(offset+2)] = STATUS_CARD_BRICKED;
            }else{
                if(pin.isValidated()){
                    buf[(short)(offset+2)] = STATUS_CARD_UNLOCKED;
                }else{
                    buf[(short)(offset+2)] = STATUS_CARD_LOCKED;
                }
            }
        }
        return (short)3;
    }
    // check if card is currently locked
    protected boolean isLocked(){
        if(!pinIsSet){
            return false;
        }
        if(pin.getTriesRemaining() == 0){
            return true;
        }
        return !pin.isValidated();
    }
    protected boolean isPinSet(){
        return pinIsSet;
    }
    /**
     * Places 32 random bytes in the buffer
     */
    private short sendRandom(byte[] msg, short msgOff, short msgLen){
        // fill buffer with 32 bytes of random data
        Crypto.random.generateData(msg, (short)0, (short)32);
        return (short)32;
    }
    public void deselect() {
        pin.reset();
    }
}