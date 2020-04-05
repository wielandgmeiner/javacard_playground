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
    static final private short PREFIX_LEN = (short)4;
    static private AESKey cardKey;
    static private AESKey hostKey;
    static private byte iv[];
    static private byte tempBuffer[];

    static public void init(){
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
        // temporary buffer for stuff
        tempBuffer = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);

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
    static public void establishSharedSecret(byte[] buf, short offset, boolean useEphimerial){
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
            Crypto.random.generateData(tempBuffer, (short)0, (short)32);
            sessionPrivateKey.setS(tempBuffer, (short)0, (short)32);
            Secp256k1.ecdh( sessionPrivateKey, 
                            buf, offset, (short)65, 
                            sharedSecret, (short)0);
        }else{
            Secp256k1.ecdh( (ECPrivateKey)staticKeyPair.getPrivate(), 
                            buf, offset, (short)65, 
                            sharedSecret, (short)0);
        }
        Crypto.sha256.reset();
        Crypto.sha256.update(CARD_PREFIX, (short)0, PREFIX_LEN);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)32, tempBuffer, (short)0);
        cardKey.setKey(tempBuffer, (short)0);

        Crypto.sha256.reset();
        Crypto.sha256.update(HOST_PREFIX, (short)0, PREFIX_LEN);
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)32, tempBuffer, (short)0);
        hostKey.setKey(tempBuffer, (short)0);
        // now we can set iv counter to zero
        Util.arrayFillNonAtomic(iv, (short)0, (short)16, (byte)0);
    }
    static public short serializeSessionPubkey(byte[] buf, short offset){
        // pubkey is just ECDH of private key with G
        Secp256k1.pointMultiply( sessionPrivateKey, 
                        Secp256k1.SECP256K1_G, (short)0, (short)65, 
                        buf, offset);
        return (short)65;
    }
    static public short authenticateData(byte[] data, short dataOffset, short dataLen, byte[] out, short outOffset){
        cardKey.getKey(tempBuffer, (short)0);
        Crypto.hmac_sha256.init(tempBuffer, (short)0, (short)32);
        return Crypto.hmac_sha256.doFinal(data, dataOffset, dataLen, out, outOffset);
    }
    // Signs arbitrary data with unique keypair
    // AFAIK signing process is deterministic so this method
    // can be used for anti-phishing words generation
    // like ColdCard's double-PIN technique
    // Recommended to hash incoming data with a prefix,
    // for example "KeyCheck" to narrow down signing
    // to a particular action
    static public short signData(byte[] data, short dataOffset, short dataLen, byte[] out, short outOffset){
        Crypto.sha256.reset();
        Crypto.sha256.doFinal(data, dataOffset, dataLen, tempBuffer, (short)0);
        return Secp256k1.sign((ECPrivateKey)staticKeyPair.getPrivate(), tempBuffer, (short)0, out, outOffset);
    }
    static public short getSharedHash(byte[] buf, short offset){
        // sending sha256 of the hostKey + cardKey
        Crypto.sha256.reset();
        hostKey.getKey(tempBuffer, (short)0);
        Crypto.sha256.update(tempBuffer, (short)0, (short)32);
        cardKey.getKey(tempBuffer, (short)0);
        Crypto.sha256.doFinal(tempBuffer, (short)0, (short)32, buf, offset);
        return (short)32;
    }
    static public short decryptMessage(byte[] ct, short ctOffset, short ctLen, byte[] out, short outOffset){
        // first we check that hmac is correct
        if(ctLen < 32){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short hmacLen = (short)32;
        // max size => drop last byte
        if(ctLen == (short)255){
            hmacLen = (short)31;
        }
        short dataLen = (short)(ctLen-hmacLen);
        // calculate expected hmac
        hostKey.getKey(tempBuffer, (short)0);
        Crypto.hmac_sha256.init(tempBuffer, (short)0, (short)32);
        Crypto.hmac_sha256.update(iv, (short)0, (short)16);
        Crypto.hmac_sha256.doFinal(ct, ctOffset, dataLen, tempBuffer, (short)0);
        // check hmac is correct
        if(Util.arrayCompare(tempBuffer, (short)0, ct, (short)(ctOffset+dataLen),hmacLen)!=(byte)0){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // decrypt using current iv value
        Crypto.cipher.init(hostKey, Cipher.MODE_DECRYPT, iv, (short)0, (short)16);
        short len = Crypto.cipher.doFinal(ct, ctOffset, dataLen, tempBuffer, (short)0);
        Util.arrayCopyNonAtomic(tempBuffer, (short)0, out, outOffset, len);
        return len;
    }
    static public short encryptMessage(byte[] data, short offset, short dataLen, byte[] cyphertext, short ctOffset){
        if(dataLen >= (short)224){
            // ciphertext + hmac wont fit in 256 bytes...
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Crypto.cipher.init(cardKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)16);
        short len = Crypto.cipher.doFinal(data, offset, dataLen, tempBuffer, (short)0);
        Util.arrayCopyNonAtomic(tempBuffer, (short)0, cyphertext, ctOffset, len);
        cardKey.getKey(tempBuffer, (short)0);
        Crypto.hmac_sha256.init(tempBuffer, (short)0, (short)32);
        Crypto.hmac_sha256.update(iv, (short)0, (short)16);
        Crypto.hmac_sha256.doFinal(cyphertext, ctOffset, len, tempBuffer, (short)0);
        short hmacLen = (short)32;
        // if we are hitting the limit
        if((short)(len+hmacLen) == (short)256){
            hmacLen = (short)31;
        }
        Util.arrayCopyNonAtomic(tempBuffer, (short)0, cyphertext, (short)(ctOffset+len), hmacLen);
        increaseIV();
        return (short)(len+hmacLen);
    }
    // TODO: refactor, ugly
    static private void increaseIV(){
        short val = (short)0;
        byte carry = (byte)1;
        for(short i=(short)15; i>=(short)0; i--){
            val = iv[i];
            if(val < (short)0){
                val = (short)(val + (short)256);
            }
            if(val == (short)255){
                val = (short)0;
                iv[i] = (byte)0;
            }else{
                carry = (byte)0;
                val = (short)(val+1);
                iv[i] = (byte)val;
                break;
            }
        }
        if(carry==(byte)1){
            closeChannel();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }
    static public void closeChannel(){
        // overwrite all secrets with random junk
        Crypto.random.generateData(sharedSecret, (short)0, (short)32);
        Crypto.random.generateData(tempBuffer, (short)0, (short)255);
        cardKey.setKey(tempBuffer, (short)0);
        hostKey.setKey(tempBuffer, (short)32);
        Util.arrayCopyNonAtomic(tempBuffer, (short)64, iv, (short)0, (short)16);
        Crypto.random.generateData(tempBuffer, (short)0, (short)255);
    }
}