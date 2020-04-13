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

    // Max storage
    private static final short MAX_DATA_LENGTH         = (short)255;

    private static final byte PIN_MAX_LENGTH           = (byte)32;
    private static final byte PIN_MAX_COUNTER          = (byte)10;

    // commands transmitted over secure channel
    private static final byte CMD_ECHO                = (byte)0x00;
    private static final byte CMD_RAND                = (byte)0x01;
    private static final byte CMD_PHISH               = (byte)0x02;
    private static final byte CMD_PIN                 = (byte)0x03;
    private static final byte CMD_WIPE                = (byte)0x04;
    private static final byte CMD_STORAGE             = (byte)0x05;
    // TODO: reestablish cahnnel without PIN lock
    // private static final byte CMD_REESTABLISH_SC      = (byte)0x06;

    private static final byte SUBCMD_DEFAULT          = (byte)0x00;
    // pin
    private static final byte SUBCMD_PIN_STATUS       = (byte)0x00;
    private static final byte SUBCMD_PIN_UNLOCK       = (byte)0x01;
    private static final byte SUBCMD_PIN_LOCK         = (byte)0x02;
    private static final byte SUBCMD_PIN_CHANGE       = (byte)0x03;
    // storage
    private static final byte SUBCMD_STORAGE_GET      = (byte)0x00;
    private static final byte SUBCMD_STORAGE_PUT      = (byte)0x01;

    // status
    private static final byte STATUS_PIN_NOT_SET      = (byte)0x00;
    private static final byte STATUS_CARD_LOCKED      = (byte)0x01;
    private static final byte STATUS_CARD_UNLOCKED    = (byte)0x02;
    private static final byte STATUS_CARD_BRICKED     = (byte)0x03;

    // errorcodes
    private static final short ERR_INVALID_LEN        = (short)0x0403;
    private static final short ERR_INVALID_CMD        = (short)0x0404;
    private static final short ERR_INVALID_SUBCMD     = (short)0x0405;
    private static final short ERR_CARD_LOCKED        = (short)0x0501;
    private static final short ERR_INVALID_PIN        = (short)0x0502;
    private static final short ERR_NO_ATTEMPTS_LEFT   = (short)0x0503;
    private static final short ERR_ALREADY_UNLOCKED   = (short)0x0504;
    private static final short ERR_NOT_INITIALIZED    = (short)0x0505;
    private static final short RESPONSE_SUCCESS       = (short)0x9000;

    private OwnerPIN pin;
    // mb better to do via GP somehow?
    private boolean pinIsSet = false;

    private DataEntry secretData;
    protected TransientStack stack;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public MemoryCardApplet(){
        super();

        stack = new TransientStack((short)1024);
        // Crypto primitives. 
        // Keep it in this order.
        Secp256k1.init(stack);
        Crypto.init(stack);
        SecureChannel.init(stack);

        pin = new OwnerPIN(PIN_MAX_COUNTER, PIN_MAX_LENGTH);

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

            // first - lock the card to avoid active MITM
            if(pinIsSet && pin.isValidated()){
                pin.reset();
            }
            setHostPubkey(apdu);
            break;
        case INS_SET_HOST_GET_EPH:
            // this one uses random keys from both parties
            // more secure, but probably uses EEPROM :(

            // first - lock the card to avoid active MITM
            if(pinIsSet && pin.isValidated()){
                pin.reset();
            }
            setHostGetEphimerial(apdu);
            break;
        case INS_SECURE_MESSAGE:
            handleSecureMessage(apdu);
            break;
        case INS_GET_RANDOM:
            sendRandom(apdu);
            break;
        case INS_CLOSE_CHANNEL:
            SecureChannel.closeChannel();
            break;
        default:
            // If we don't know the INS, 
            // pass it to the parent
            super.process(apdu);
        }
    }
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
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short len = Util.makeShort((byte)0, buf[ISO7816.OFFSET_LC]);
        len = SecureChannel.decryptMessage(buf, ISO7816.OFFSET_CDATA, len, buf, (short)0);
        // processes message and returns len of the responce to send back to host
        // responce is placed back to the same buffer
        len = processSecureMessage(buf, (short)0, len);
        // encrypt buffer and send to the host
        len = SecureChannel.encryptMessage(buf, (short)0, len, buf, (short)0);
        apdu.setOutgoingAndSend((short)0, len);
    }
    private short processSecureMessage(byte[] buf, short offset, short len){
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
            case CMD_STORAGE:
                return processStorageCommand(buf, offset, len);
            default:
                return sendError(ERR_INVALID_CMD, buf, offset);
        }
    }
    private short sendError(short errorcode, byte[] buf, short offset){
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
    private short processStorageCommand(byte[] buf, short offset, short len){
        if(isLocked()){
            return sendError(ERR_CARD_LOCKED, buf, offset);
        }
        byte subcmd = buf[(short)(offset+1)];
        buf[offset] = (byte)0x90;
        buf[(short)(offset+1)] = (byte)0x00;
        switch (subcmd){
            case SUBCMD_STORAGE_GET:
                Util.arrayCopyNonAtomic(secretData.get(), (short)0, buf, (short)(offset+2), secretData.length());
                return (short)(2+secretData.length());
            case SUBCMD_STORAGE_PUT:
                secretData.put(buf, (short)2, (short)(len-2));
                return (short)2;
            default:
                return sendError(ERR_INVALID_SUBCMD, buf, offset);
        }
    }
    // check if card is currently locked
    private boolean isLocked(){
        if(!pinIsSet){
            return false;
        }
        if(pin.getTriesRemaining() == 0){
            return true;
        }
        return !pin.isValidated();
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
    public void deselect() {
        pin.reset();
    }
}