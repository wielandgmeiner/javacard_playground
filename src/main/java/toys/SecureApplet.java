package toys;

// import using java card API interface.
import javacard.framework.*;

/**
 * A base secure applet that includes a PIN code and secure communication channel.
 * <p>
 * It registeres a set of APDU commands to establish secure channel,
 * to receive secure message and to manage the PIN code.
 * <p>
 * In derived applet define the following functions:
 * <ul>
 * <li> {@code processPlainMessage}  - to process any non-encrypted messages
 * <li> {@code processSecureMessage} - to process any encrypted message 
 *                             (data passed to this function is already decrypted and verified)
 * <li> TODO: {@code postUnlock(PIN)} and {@code preUnlock(PIN)} - methods is called before and after PIN is verified.
 * <li> TODO: {@code postChangePIN(oldPIN, newPIN)} - method is called when PIN is changed
 * <li> TODO: {@code postLock()} - method is called when card is locked.
 * <p>
 * Plaintext instruction codes INS from 0xB1 to 0xB7 are reserved for secure channel:
 * <ul>
 * <li>{@code B1} - returns 32 bytes of random data from built-in RNG
 * <li>{@code B2} - returns a static public key for key agreement. 
 *                        Serialized, uncompressed (65-bytes, {@code <04><x><y>})
 * <li>TODO: {@code B3} - Establishes secure channel in SS mode.
 * <li>{@code B4} - Establishes secure channel in ES mode. 
 *                  Card uses static key, host should send ephemeral key.
 * <li>{@code B5} - Establishes secure channel in EE mode. 
 *                  Both the card and the host use ephemeral key.
 * <li>{@code B6} - Process secure message.
 * <li>{@code B7} - Close secure channel.
 * <p>
 * Encrypted command codes CMD from 0x00 to 0x04 are reserved 
 * for PIN code management and a few other commands:
 * <ul>
 * <li>{@code 00} - echo back what was sent to the card. Useful to check secure channel.
 * <li>{@code 01} - send 32 bytes of random data over secure channel. 
 *                  Useful to get some extra entropy for key generation on the host.
 * <li>TODO: {@code 02} - authenticate data with internal secret.
 *                  Can be used to generate anti-phishing byte sequence while user is entering 
 *                  the PIN code to proof to the user that the card was not replaced.
 * <li>{@code 03} - PIN management commands.
 * <li>TODO: {@code 04} - Reestablish channel without locking the card (just rotate keys).
 * <li>TODO: {@code 05} - Wipe everything on the card. 
 */
public class SecureApplet extends Applet{

    /** Instruction to get 32 random bytes, without secure channel */
    private static final byte INS_GET_RANDOM                  = (byte)0xB1;

    /* Secure channel stuff */
    /** Instruction to get static card's public key for ECDH key agreement */
    private static final byte INS_GET_CARD_PUBKEY             = (byte)0xB2;
    /** Instruction to establish secure channel in ES mode - 
     *  ephemeral key from the host, static key from the card. */
    private static final byte INS_OPEN_SECURE_CHANNEL_SS_MODE = (byte)0xB3;
    /** Instruction to establish secure channel in ES mode - 
     *  ephemeral keys are used both on the host and on the card. */
    private static final byte INS_OPEN_SECURE_CHANNEL_ES_MODE = (byte)0xB4;
    /** Instruction to establish secure channel in EE mode - 
     *  ephemeral keys are used both on the host and on the card. */
    private static final byte INS_OPEN_SECURE_CHANNEL_EE_MODE = (byte)0xB5;
    private static final byte INS_SECURE_MESSAGE              = (byte)0xB6;
    private static final byte INS_CLOSE_CHANNEL               = (byte)0xB7;

    /* Commands transmitted over secure channel */
    private static final byte CMD_ECHO                  = (byte)0x00;
    private static final byte CMD_RAND                  = (byte)0x01;
    private static final byte CMD_AUTH                  = (byte)0x02;
    private static final byte CMD_PIN                   = (byte)0x03;
    private static final byte CMD_REESTABLISH_SC        = (byte)0x04;
    private static final byte CMD_WIPE                  = (byte)0x05;

    protected static final byte SUBCMD_DEFAULT          = (byte)0x00;
    // pin
    private static final byte SUBCMD_PIN_STATUS         = (byte)0x00;
    private static final byte SUBCMD_PIN_UNLOCK         = (byte)0x01;
    private static final byte SUBCMD_PIN_LOCK           = (byte)0x02;
    private static final byte SUBCMD_PIN_CHANGE         = (byte)0x03;

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

    /* PIN constants */
    private static final byte PIN_MAX_LENGTH            = (byte)32;
    private static final byte PIN_MAX_COUNTER           = (byte)10;
    
    private OwnerPIN pin;
    // mb better to do via GP somehow?
    private boolean pinIsSet = false;

    protected TransientHeap heap;
    protected SecureChannel sc;

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
        sc = new SecureChannel(heap);
        pin = new OwnerPIN(PIN_MAX_COUNTER, PIN_MAX_LENGTH);
    }
    /** Redefine this function in your applet to process secure message
     *  return number of bytes written in the buffer
     *  you can write starting from offset 0 */
    protected short processSecureMessage(byte[] buf, short offset, short len){
        ISOException.throwIt(ERR_INVALID_CMD);
        return (short)2;
    }
    /** Redefine this function in your applet to handle plaintext message
     *  return number of bytes written in the buffer
     *  you can write starting from offset 0
     *  WARNING: no secure channel means MITM attack possibility */
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
        byte[] buf = apdu.getBuffer();
        short dataLen = apdu.getIncomingLength();
        short dataOff = ISO7816.OFFSET_CDATA;
        apdu.setIncomingAndReceive();

        short len = 0;
        // TODO: check CLA to be 0xB0?
        // Dispatch INS in APDU.
        switch (buf[ISO7816.OFFSET_INS]){
        case INS_GET_CARD_PUBKEY:
            len = sendCardPubkey(buf, (short)0);
            break;
        case INS_OPEN_SECURE_CHANNEL_ES_MODE:
            // this one uses random key from host and
            // static key from card - simple key agreement

            // first - lock the card to avoid active MITM
            lock();
            len = setHostPubkey(buf, dataOff, dataLen);
            break;
        case INS_OPEN_SECURE_CHANNEL_EE_MODE:
            // this one uses random keys from both parties
            // more secure, but probably uses EEPROM :(

            // first - lock the card to avoid active MITM
            lock();
            len = setHostGetEphimerial(buf, dataOff, dataLen);
            break;
        case INS_SECURE_MESSAGE:
            // Try to handle secure message
            // Only secure channel exceptions will get here
            // as internal exceptions are caught and transmitted
            // over secure channel
            try {
                len = handleSecureMessage(buf, dataOff, dataLen);
            } catch (CardRuntimeException e) {
                // something is wrong with secure channel
                // so we close channel and lock the card
                sc.closeChannel();
                lock();
                // reraise
                ISOException.throwIt(e.getReason());
            }
            break;
        case INS_GET_RANDOM:
            len = sendRandom(buf, dataOff, dataLen);
            break;
        case INS_CLOSE_CHANNEL:
            // close secure channel
            sc.closeChannel();
            // lock the card
            lock();
            break;
        default:
            len = processPlainMessage(buf, dataOff, dataLen);
        }
        apdu.setOutgoingAndSend((short)0, len);
    }
    /** Puts unique public key of the card to the message buffer */
    private short sendCardPubkey(byte[] buf, short off){
        return sc.serializeStaticPublicKey(buf, off);
    }
    private short setHostPubkey(byte[] msg, short msgOff, short msgLen){
        // check if data length is ok
        if(msgLen != (short)97){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return (short)0;
        }
        // will put nonce there
        short len = sc.establishSharedSecret(msg, msgOff, SecureChannel.MODE_ES, msg, (short)0);
        // get hash of the shared secret and put it to the buffer
        len += sc.getSharedFingerprint(msg, len);
        // add hmac using shared secret
        len += sc.authenticateData(msg, (short)0, len, msg, len);
        // add signature with static pubkey
        len += sc.signData(msg, (short)0, len, msg, len);
        return len;
    }
    private short setHostGetEphimerial(byte[] msg, short msgOff, short msgLen){
        // check if data length is ok
        if(msgLen != (byte)65){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return (short)0;
        }
        // for consistency with se mode
        sc.establishSharedSecret(msg, msgOff, SecureChannel.MODE_EE, msg, (short)0);
        // get session pubkey and put it to the buffer
        short len = sc.serializeSessionPubkey(msg, (short)0);
        // add hmac using shared secret
        len += sc.authenticateData(msg, (short)0, len, msg, len);
        // add signature with static pubkey
        len += sc.signData(msg, (short)0, len, msg, len);
        return len;
    }
    private short handleSecureMessage(byte[] msg, short msgOff, short msgLen){
        short len = sc.decryptMessage(msg, msgOff, msgLen, msg, (short)0);
        try{
            // processes message and returns len of the responce to send back to host
            // responce is placed back to the same buffer
            len = preprocessSecureMessage(msg, (short)0, len);
        // code can throw an exception and 
        // it will be transmitted over secure channel
        // TODO: catch ISOException and transmit as is
        //       for others - transmit general errorcode
        }catch(CardRuntimeException e){
            len = sendError(e.getReason(), msg, (short)0);
        }
        // return len;
        // encrypt buffer and send to the host
        return sc.encryptMessage(msg, (short)0, len, msg, (short)0);
    }
    private short preprocessSecureMessage(byte[] buf, short offset, short len){
        if(len < 2){
            ISOException.throwIt(ERR_INVALID_LEN);
            return (short)2;
        }
        switch (buf[offset]){
            case CMD_ECHO:
                if(buf[(short)(offset+1)] == SUBCMD_DEFAULT){
                    return sendEcho(buf, offset, len);
                }else{
                    ISOException.throwIt(ERR_INVALID_SUBCMD);
                }
                return (short)2;
            case CMD_RAND:
                if(buf[(short)(offset+1)] == SUBCMD_DEFAULT){
                    return sendSecRand(buf, offset, len);
                }else{
                    ISOException.throwIt(ERR_INVALID_SUBCMD);
                }
                return (short)2;
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
                            ISOException.throwIt(ERR_INVALID_LEN);
                            return (short)2;
                        }
                        if(pin.getTriesRemaining() == 0){
                            ISOException.throwIt(ERR_NO_ATTEMPTS_LEFT);
                            return (short)2;
                        }
                        if(!pin.check(buf, (short)(offset+2), (byte)(len-2))){
                            ISOException.throwIt(ERR_INVALID_PIN);
                            return (short)2;
                        }
                    }else{
                        ISOException.throwIt(ERR_ALREADY_UNLOCKED);
                        return (short)2;
                    }
                }else{
                    if(len > (short)(PIN_MAX_LENGTH+2)){
                        ISOException.throwIt(ERR_INVALID_LEN);
                        return (short)2;
                    }
                    // TODO: wrap in transaction
                    pin.update(buf, (short)(offset+2), (byte)(len-2));
                    pinIsSet = true;
                }
                return (short)2;
            case SUBCMD_PIN_LOCK:
                lock();
                return (short)2;
            case SUBCMD_PIN_CHANGE:
                // check data lengths
                if(len < (short)4){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                short len_old = Util.makeShort((byte)0, buf[(short)(offset+2)]);
                if(len_old > (short)PIN_MAX_LENGTH){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                if(len < (short)(4+len_old)){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                short len_new = Util.makeShort((byte)0, buf[(short)(offset+3+len_old)]);
                if(len_new > (short)PIN_MAX_LENGTH){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                if(len != (short)(4+len_old+len_new)){
                    ISOException.throwIt(ERR_INVALID_LEN);
                }
                if(!pinIsSet){
                    ISOException.throwIt(ERR_NOT_INITIALIZED);
                }
                if(!pin.isValidated()){
                    ISOException.throwIt(ERR_CARD_LOCKED);
                }
                if(!pin.check(buf, (short)(offset+3), (byte)len_old)){
                    ISOException.throwIt(ERR_INVALID_PIN);
                }else{
                    pin.update(buf, (short)(offset+4+len_old), buf[(short)(offset+3+len_old)]);
                }
                return (short)2;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return (short)2;
    }
    /** Locks the card */
    protected void lock(){
        if(pinIsSet && pin.isValidated()){
            pin.reset();
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