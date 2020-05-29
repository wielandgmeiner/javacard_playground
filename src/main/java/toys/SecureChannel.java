package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Secure channel class to manage secure communication with the host.
 * <p>
 * When class instance is initiated it creates a static key pair
 * that can be used to make sure the card is the same.
 * <p>
 * This key pair is also used to establish a shared secret using
 * EE (ephemeral keys on both sides), ES (ephemeral key on the card) 
 * or SS (both keys are static) mode for key agreement algorithm.
 */
public class SecureChannel{
    /** Use ephemeral keys on both sides to establish secure channel */
    static final public byte MODE_EE = (byte)0x01;
    /** Use static key on the card to establish secure channel */
    static final public byte MODE_ES = (byte)0x02;
    /** Use static keys on both sides to establish secure channel */
    static final public byte MODE_SS = (byte)0x03;

    /** Key size for AES */
    static final public short AES_KEY_SIZE = (short)32;
    /** Key size for HMAC */
    static final public short MAC_KEY_SIZE = (short)32;
    /** Shared secret size */
    static final public short SHARED_SECRET_SIZE = (short)32;
    /** EC key size */
    static final public short EC_PRIVATE_KEY_SIZE = (short)32;
    /** EC public key size */
    static final public short EC_PUBLIC_KEY_SIZE = (short)65;
    /** Max of AES, HMAC, EC and SharedSecret key size for efficient heap allocations */
    static final public short MAX_KEY_SIZE = (short)32;
    /** 
     * Size of the HMAC code used in messages. 
     * We reduce it to 15 bytes to increase data capacity. 
     */
    static final public short MAC_SIZE = (short)15;
    /** Size of the IV for AES */
    static final public short IV_SIZE = (short)16;
    /** Size of the fingerprint */
    static final public short FINGERPRINT_LEN = (short)4;

    /** Static key pair generated when class instance is created */
    private KeyPair staticKeyPair;
    /** Ephemeral private key for channel establishment */
    private ECPrivateKey ephemeralPrivateKey;

    private byte sharedSecret[];
    /** Prefix to derive card keys from shared secret */
    static final private byte CARD_PREFIX[] = { 'c', 'a', 'r', 'd' };
    /** Prefix to derive host keys from shared secret */
    static final private byte HOST_PREFIX[] = { 'h', 'o', 's', 't' };
    /** Prefix to derive AES keys from shared secret */
    static final private byte AES_PREFIX[] = { '_', 'a', 'e', 's' };
    /** Prefix to derive HMAC keys from shared secret */
    static final private byte MAC_PREFIX[] = { '_', 'm', 'a', 'c' };
    
    /** AES card key, used to encrypt messages returned from the card */
    private AESKey cardAESKey;
    /** AES host key, used to decrypt messages coming from the host */
    private AESKey hostAESKey;
    /** HMAC card key, used to authenticate data returned from the card */
    private byte cardMACKey[];
    /** HMAC host key, used to check authentication of incoming data */
    private byte hostMACKey[];
    /** 
     * Initialization vector for AES encryption/decryption.
     * Used in a counter mode - increased by 1 on every message.
     */
    private byte iv[];
    /**
     * TransientHeap instance that is used to temporarly allocate memory
     * for some internal operations.
     */
    private TransientHeap heap;

    /**
     * Constructor for SecureChannel.
     * @param hp - TransientHeap instance to use for internal temporary memory allocations.
     */
    public SecureChannel(TransientHeap hp){
        heap = hp;
        // generate random secret key for secure communication
        staticKeyPair = Secp256k1.newKeyPair();
        staticKeyPair.genKeyPair();
        // generate random session key pair 
        ephemeralPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(ephemeralPrivateKey);
        sharedSecret = JCSystem.makeTransientByteArray(SHARED_SECRET_SIZE, JCSystem.CLEAR_ON_DESELECT);
        iv = JCSystem.makeTransientByteArray(IV_SIZE, JCSystem.CLEAR_ON_DESELECT);

        cardAESKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        hostAESKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        hostMACKey = JCSystem.makeTransientByteArray(MAC_KEY_SIZE, JCSystem.CLEAR_ON_DESELECT);
        cardMACKey = JCSystem.makeTransientByteArray(MAC_KEY_SIZE, JCSystem.CLEAR_ON_DESELECT);
        // even though the channel is not open yet, we close it
        // that overwrites all keys with random junk
        closeChannel();
    }
    /**
     * Get static public key of the channel generated in the constructor.
     * @return static public key as ECPublicKey instance
     */
    public ECPublicKey getStaticPublicKey(){
        return (ECPublicKey)staticKeyPair.getPublic();
    }
    /**
     * Get static public key of the secure channel generated in the constructor
     * in uncompressed serialized format (65 bytes, {@code <04><x><y>})
     * @param buf - bytearray to put public key in
     * @param offset - position where to start
     * @return number of bytes written to the buffer (65)
     */
    public short serializeStaticPublicKey(byte[] buf, short offset){
        ECPublicKey pub = getStaticPublicKey();
        return pub.getW(buf, offset);
    }
    public short establishSharedSecret(byte[] buf, short offset, 
                                       byte mode,
                                       byte[] out, short outOff){
        short len = MAX_KEY_SIZE;
        short off = heap.allocate(len);
        short outLen = (short)0;
        // first we wipe what we already have
        closeChannel();
        // now we establish new shared secret
        switch(mode){
        case MODE_EE:
            // generate random key pair
            Crypto.random.generateData(heap.buffer, off, EC_PRIVATE_KEY_SIZE);
            ephemeralPrivateKey.setS(heap.buffer, off, EC_PRIVATE_KEY_SIZE);
            Secp256k1.ecdh( ephemeralPrivateKey, 
                            buf, offset, EC_PUBLIC_KEY_SIZE, 
                            sharedSecret, (short)0);
            break;
        default:
            Secp256k1.ecdh( (ECPrivateKey)staticKeyPair.getPrivate(), 
                            buf, offset, EC_PUBLIC_KEY_SIZE, 
                            heap.buffer, off);
            Crypto.sha256.reset();
            // shared secret
            Crypto.sha256.update(heap.buffer, off, (short)32);
            // host nonce
            Crypto.sha256.update(buf, (short)(offset+65), (short)32);
            // card nonce
            Crypto.random.generateData(out, outOff, (short)32);
            Crypto.sha256.doFinal(out, outOff, (short)32, sharedSecret, (short)0);
            outLen += 32;
        }
        heap.free(len);
        // derive AES and MAC keys
        deriveKeys();
        // now we can set iv counter to zero
        Util.arrayFillNonAtomic(iv, (short)0, (short)iv.length, (byte)0);
        return outLen;
    }
    /**
     * Derives AES and MAC keys for the card from shared secret
     */
    private void deriveKeys(){
        short len = AES_KEY_SIZE;
        short off = heap.allocate(len);

        // card AES key
        Crypto.sha256.reset();
        Crypto.sha256.update(CARD_PREFIX, (short)0, (short)CARD_PREFIX.length);
        Crypto.sha256.update(AES_PREFIX, (short)0, (short)AES_PREFIX.length);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)sharedSecret.length, heap.buffer, off);
        cardAESKey.setKey(heap.buffer, off);

        // host AES key
        Crypto.sha256.reset();
        Crypto.sha256.update(HOST_PREFIX, (short)0, (short)HOST_PREFIX.length);
        Crypto.sha256.update(AES_PREFIX, (short)0, (short)AES_PREFIX.length);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)32, heap.buffer, off);
        hostAESKey.setKey(heap.buffer, off);

        // card MAC key
        Crypto.sha256.reset();
        Crypto.sha256.update(CARD_PREFIX, (short)0, (short)CARD_PREFIX.length);
        Crypto.sha256.update(MAC_PREFIX, (short)0, (short)MAC_PREFIX.length);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)sharedSecret.length, cardMACKey, (short)0);

        // host MAC key
        Crypto.sha256.reset();
        Crypto.sha256.update(HOST_PREFIX, (short)0, (short)HOST_PREFIX.length);
        Crypto.sha256.update(MAC_PREFIX, (short)0, (short)MAC_PREFIX.length);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)sharedSecret.length, hostMACKey, (short)0);

        heap.free(len);
    }
    public short serializeSessionPubkey(byte[] buf, short offset){
        // pubkey is just ECDH of private key with G
        return Secp256k1.pointMultiply( ephemeralPrivateKey, 
                        Secp256k1.SECP256K1_G, (short)0, (short)65, 
                        buf, offset);
    }
    /**
     * Authenticates data with card's session MAC key.
     * @param data - buffer containing data to authenticate
     * @param dataOffset - offset of the data in the buffer
     * @param dataLen - length of the data in the buffer
     * @param out - output buffer to write authentication to
     * @param outOffset - offset of the output buffer where to start
     * @return number of bytes written to the buffer
     */
    public short authenticateData(byte[] data, short dataOffset, short dataLen, 
                                         byte[] out, short outOffset){
        Crypto.hmacSha256.init(cardMACKey, (short)0, (short)cardMACKey.length);
        Crypto.hmacSha256.doFinal(data, dataOffset, dataLen, out, outOffset);
        return (short)32;
    }
    /** 
     * Signs arbitrary data with unique keypair
     * AFAIK signing process is deterministic so this method
     * can be used for anti-phishing words generation
     * like ColdCard's double-PIN technique
     * <br>
     * Better to hash incoming data with a prefix,
     * for example "KeyCheck" to narrow down signing
     * to a particular action
     * @param data - buffer with data to sign
     * @param dataOffset - offset of the data in the buffer
     * @param dataLen - length of the data to sign
     * @param out - output buffer to put a signature
     * @param outOffset - offset in the output buffer
     * @return number of bytes written to the output buffer
     */
    public short signData(byte[] data, short dataOffset, short dataLen, 
                                 byte[] out, short outOffset){
        short len = (short)Crypto.sha256.getLength();
        short off = heap.allocate(len);

        Crypto.sha256.reset();
        Crypto.sha256.doFinal(data, dataOffset, dataLen, heap.buffer, off);
        short sigLen = Secp256k1.sign((ECPrivateKey)staticKeyPair.getPrivate(), heap.buffer, off, out, outOffset);
        heap.free(len);
        return sigLen;
    }
    /**
     * Writes a fingerprint to the buffer (first 4 bytes of sha256 of shared secret)
     * @param buf - buffer to write fingerprint to
     * @param offset - offset where to start
     * @return number of bytes written (4)
     */
    public short getSharedFingerprint(byte[] buf, short offset){
        // sending first 4 bytes of sha256(shared secret)
        short len = (short)Crypto.sha256.getLength();
        short off = heap.allocate(len);

        Crypto.sha256.reset();
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)sharedSecret.length, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, buf, offset, FINGERPRINT_LEN);
        heap.free(len);
        return FINGERPRINT_LEN;
    }
    /**
     * Dectypts message, also checks authentication code.
     * @param ct - buffer with the cyphertext to decrypt
     * @param ctOffset - offset of the cyphertext in the buffer
     * @param ctLen - length of the cyphertext including MAC
     * @param out - output buffer to put decrypted message to
     * @param outOffset - offest in the output buffer
     * @return number of bytes of the resulting plaintext message
     */
    public short decryptMessage(byte[] ct, short ctOffset, short ctLen, 
                                       byte[] out, short outOffset){
        // first we check that hmac is correct
        if(ctLen < 32){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short len = (short)255;
        short off = heap.allocate(len);
        short hmacLen = (short)32;
        // max size => drop last byte
        if(ctLen == (short)255){
            hmacLen = (short)31;
        }
        short dataLen = (short)(ctLen-hmacLen);
        // calculate expected hmac
        Crypto.hmacSha256.init(hostMACKey, (short)0, (short)hostMACKey.length);
        Crypto.hmacSha256.update(iv, (short)0, (short)iv.length);
        Crypto.hmacSha256.doFinal(ct, ctOffset, dataLen, heap.buffer, off);
        // check hmac is correct
        if(Util.arrayCompare(heap.buffer, off, ct, (short)(ctOffset+dataLen),hmacLen)!=(byte)0){
            closeChannel();
            heap.free(len);
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // decrypt using current iv value
        Crypto.cipher.init(hostAESKey, Cipher.MODE_DECRYPT, iv, (short)0, (short)iv.length);
        short plainLen = Crypto.cipher.doFinal(ct, ctOffset, dataLen, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, out, outOffset, plainLen);
        heap.free(len);
        return plainLen;
    }
    /**
     * Encrypts message and appends authentication code
     * @param data - buffer containing data to encrypt
     * @param offset - offset of the data in the input buffer
     * @param dataLen - length of the data
     * @param cyphertext - buffer to put cyphertext to
     * @param ctOffset - offset of the output buffer
     * @return number of bytes written to the output buffer
     */
    public short encryptMessage(byte[] data, short offset, short dataLen, 
                                       byte[] cyphertext, short ctOffset){
        if(dataLen >= (short)224){
            // ciphertext + hmac wont fit in 256 bytes...
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short len = (short)(iv.length+255);
        short ivOffOld = heap.allocate(len);
        short off = (short)(ivOffOld + iv.length);
        // copy IV value to temp buffer and increase IV
        Util.arrayCopyNonAtomic(iv, (short)0, heap.buffer, ivOffOld, (short)iv.length);
        increaseIV();

        Crypto.cipher.init(cardAESKey, Cipher.MODE_ENCRYPT, heap.buffer, ivOffOld, (short)iv.length);
        short ctLen = Crypto.cipher.doFinal(data, offset, dataLen, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, cyphertext, ctOffset, ctLen);
        Crypto.hmacSha256.init(cardMACKey, (short)0, (short)cardMACKey.length);
        Crypto.hmacSha256.update(heap.buffer, ivOffOld, (short)iv.length);
        Crypto.hmacSha256.doFinal(cyphertext, ctOffset, ctLen, heap.buffer, off);
        short hmacLen = (short)32;
        // if we are hitting the limit
        if((short)(ctLen+hmacLen) == (short)256){
            hmacLen = (short)31;
        }
        Util.arrayCopyNonAtomic(heap.buffer, off, cyphertext, (short)(ctOffset+ctLen), hmacLen);
        heap.free(len);
        return (short)(ctLen+hmacLen);
    }
    /** Increases IV by 1 */
    private void increaseIV(){
        short carry = 1;
        for(short i=(short)(iv.length-1); i>=0; i--){
            carry += (iv[i]&0xFF);
            iv[i] = (byte)carry;
            carry >>= 8;
        }
        if(carry!=0){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }
    /**
     * Close secure channel.
     * <p>
     * Overwrites all secret keys with random data.
     */
    public void closeChannel(){
        // fill with random data to make sure that
        // nobody can talk to the card anymore
        Crypto.random.generateData(iv, (short)0, (short)iv.length);
        Crypto.random.generateData(hostMACKey,   (short)0, (short)hostMACKey.length);
        Crypto.random.generateData(cardMACKey,   (short)0, (short)cardMACKey.length);
        Crypto.random.generateData(sharedSecret, (short)0, (short)sharedSecret.length);

        // we generate random data to the heap temp buffer and
        // reuse this buffer to set this random data as AES keys
        short len = AES_KEY_SIZE;
        short off = heap.allocate(len);
        Crypto.random.generateData(heap.buffer, off, AES_KEY_SIZE);
        cardAESKey.setKey(heap.buffer, off);
        Crypto.random.generateData(heap.buffer, off, AES_KEY_SIZE);
        hostAESKey.setKey(heap.buffer, off);
        // free heap
        heap.free(len);
    }
}