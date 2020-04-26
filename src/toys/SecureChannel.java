/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/* 
 * Package: toys
 * Filename: SecureChannel.java 
 * Class: SecureChannel
 */
public class SecureChannel{
    // Unique key pair generated on applet setup
    // Public key can be checked by the host to verify 
    // that the card is the same.
    // Arbitrary data can be signed with .sign() method
    // to verify that the card actually has private key
    static private KeyPair staticKeyPair;
    static private ECPrivateKey sessionPrivateKey;
    static private boolean sessionIsTransient = false;

    static private byte sharedSecret[];
    static final private byte CARD_PREFIX[] = { (byte)'c', (byte)'a', (byte)'r', (byte)'d' };
    static final private byte HOST_PREFIX[] = { (byte)'h', (byte)'o', (byte)'s', (byte)'t' };
    static private AESKey cardKey;
    static private AESKey hostKey;
    static private byte iv[];
    static protected TransientHeap heap;

    static public void init(TransientHeap hp){
        heap = hp;
        // generate random secret key for secure communication
        staticKeyPair = Secp256k1.newKeyPair();
        staticKeyPair.genKeyPair();
        // generate random session key pair 
        // - will be cleared every time on reset / deselect
        try {
            sessionPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
            sessionIsTransient = true;
        }
        catch(CryptoException e) {
            try {
                sessionPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
                sessionIsTransient = true;
            }
            catch(CryptoException e1) {
                sessionPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
                Secp256k1.setCommonCurveParameters(sessionPrivateKey);
            }
        }
        // fill with random data to make sure that
        // at first nobody can talk to the card
        sharedSecret = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        Crypto.random.generateData(sharedSecret, (short)0, (short)32);
        iv = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        Crypto.random.generateData(iv, (short)0, (short)16);

        cardKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        hostKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    }
    static public ECPublicKey getStaticPubkey(){
        return (ECPublicKey)staticKeyPair.getPublic();
    }
    static public short serializeStaticPubkey(byte[] buf, short offset){
        ECPublicKey pub = getStaticPubkey();
        pub.getW(buf, offset);
        return (short)65;
    }
    static public short establishSharedSecret(byte[] buf, short offset, 
                                             boolean useEphimerial,
                                             byte[] out, short outOff){
        short len = (short)32;
        short off = heap.allocate(len);
        short outLen = (short)0;
        // first we wipe what we already have
        closeChannel();
        // now we establish new shared secret
        if(useEphimerial){
            // generate random key pair
            // as session key pair is transient 
            // we need to set curve every time?
            // TODO: check
            if(sessionIsTransient){
                Secp256k1.setCommonCurveParameters(sessionPrivateKey);
            }
            Crypto.random.generateData(heap.buffer, off, (short)32);
            sessionPrivateKey.setS(heap.buffer, off, (short)32);
            Secp256k1.ecdh( sessionPrivateKey, 
                            buf, offset, (short)65, 
                            sharedSecret, (short)0);
        }else{
            Secp256k1.ecdh( (ECPrivateKey)staticKeyPair.getPrivate(), 
                            buf, offset, (short)65, 
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
        Crypto.sha256.reset();
        Crypto.sha256.update(CARD_PREFIX, (short)0, (short)CARD_PREFIX.length);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)32, heap.buffer, off);
        cardKey.setKey(heap.buffer, off);

        Crypto.sha256.reset();
        Crypto.sha256.update(HOST_PREFIX, (short)0, (short)HOST_PREFIX.length);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)32, heap.buffer, off);
        hostKey.setKey(heap.buffer, off);
        // now we can set iv counter to zero
        Util.arrayFillNonAtomic(iv, (short)0, (short)16, (byte)0);
        heap.free(len);
        return outLen;
    }
    static public short serializeSessionPubkey(byte[] buf, short offset){
        // pubkey is just ECDH of private key with G
        Secp256k1.pointMultiply( sessionPrivateKey, 
                        Secp256k1.SECP256K1_G, (short)0, (short)65, 
                        buf, offset);
        return (short)65;
    }
    static public short authenticateData(byte[] data, short dataOffset, short dataLen, 
                                         byte[] out, short outOffset){
        short len = (short)32;
        short off = heap.allocate(len);

        cardKey.getKey(heap.buffer, off);
        Crypto.hmacSha256.init(heap.buffer, off, (short)32);
        Crypto.hmacSha256.doFinal(data, dataOffset, dataLen, out, outOffset);
        heap.free(len);
        return (short)32;
    }
    // Signs arbitrary data with unique keypair
    // AFAIK signing process is deterministic so this method
    // can be used for anti-phishing words generation
    // like ColdCard's double-PIN technique
    // Recommended to hash incoming data with a prefix,
    // for example "KeyCheck" to narrow down signing
    // to a particular action
    static public short signData(byte[] data, short dataOffset, short dataLen, 
                                 byte[] out, short outOffset){
        short len = (short)32;
        short off = heap.allocate(len);

        Crypto.sha256.reset();
        Crypto.sha256.doFinal(data, dataOffset, dataLen, heap.buffer, off);
        short sigLen = Secp256k1.sign((ECPrivateKey)staticKeyPair.getPrivate(), heap.buffer, off, out, outOffset);
        heap.free(len);
        return sigLen;
    }
    static public short getSharedHash(byte[] buf, short offset){
        // sending sha256 of the hostKey + cardKey
        short len = (short)32;
        short off = heap.allocate(len);

        Crypto.sha256.reset();
        hostKey.getKey(heap.buffer, off);
        Crypto.sha256.update(heap.buffer, off, (short)32);
        cardKey.getKey(heap.buffer, off);
        Crypto.sha256.doFinal(heap.buffer, off, (short)32, buf, offset);
        heap.free(len);
        return (short)32;
    }
    static public short decryptMessage(byte[] ct, short ctOffset, short ctLen, 
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
        hostKey.getKey(heap.buffer, off);
        Crypto.hmacSha256.init(heap.buffer, off, (short)32);
        Crypto.hmacSha256.update(iv, (short)0, (short)16);
        Crypto.hmacSha256.doFinal(ct, ctOffset, dataLen, heap.buffer, off);
        // check hmac is correct
        if(Util.arrayCompare(heap.buffer, off, ct, (short)(ctOffset+dataLen),hmacLen)!=(byte)0){
            closeChannel();
            heap.free(len);
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // decrypt using current iv value
        Crypto.cipher.init(hostKey, Cipher.MODE_DECRYPT, iv, (short)0, (short)16);
        short plainLen = Crypto.cipher.doFinal(ct, ctOffset, dataLen, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, out, outOffset, plainLen);
        heap.free(len);
        return plainLen;
    }
    static public short encryptMessage(byte[] data, short offset, short dataLen, 
                                       byte[] cyphertext, short ctOffset){
        if(dataLen >= (short)224){
            // ciphertext + hmac wont fit in 256 bytes...
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short len = (short)255;
        short off = heap.allocate(len);

        Crypto.cipher.init(cardKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)16);
        short ctLen = Crypto.cipher.doFinal(data, offset, dataLen, heap.buffer, off);
        Util.arrayCopyNonAtomic(heap.buffer, off, cyphertext, ctOffset, ctLen);
        cardKey.getKey(heap.buffer, off);
        Crypto.hmacSha256.init(heap.buffer, off, (short)32);
        Crypto.hmacSha256.update(iv, (short)0, (short)16);
        Crypto.hmacSha256.doFinal(cyphertext, ctOffset, ctLen, heap.buffer, off);
        short hmacLen = (short)32;
        // if we are hitting the limit
        if((short)(ctLen+hmacLen) == (short)256){
            hmacLen = (short)31;
        }
        Util.arrayCopyNonAtomic(heap.buffer, off, cyphertext, (short)(ctOffset+ctLen), hmacLen);
        increaseIV();
        heap.free(len);
        return (short)(ctLen+hmacLen);
    }
    static private void increaseIV(){
        short carry = 1;
        for(short i=15; i>=0; i--){
            carry += (iv[i]&0xFF);
            iv[i] = (byte)carry;
            carry >>= 8;
        }
        if(carry!=0){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }
    static public void closeChannel(){
        // overwrite all secrets with random junk
        Crypto.random.generateData(sharedSecret, (short)0, (short)32);
        cardKey.setKey(sharedSecret, (short)0);
        Crypto.random.generateData(sharedSecret, (short)0, (short)32);
        hostKey.setKey(sharedSecret, (short)0);
        Crypto.random.generateData(sharedSecret, (short)0, (short)32);
        Util.arrayFillNonAtomic(iv, (short)0, (short)16, (byte)0x00);
    }
}