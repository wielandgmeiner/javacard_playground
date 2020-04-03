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
    static public KeyPair uniqueKeyPair;
    static private byte[] sharedSecret;
    static private Key sharedKey;
    static private byte[] iv;
    static private byte[] tempBuffer;

    static public void init(){
        // generate random secret key for secure communication
        uniqueKeyPair = Secp256k1.newKeyPair();
        uniqueKeyPair.genKeyPair();
        // fill with random data to make sure that
        // at first nobody can talk to the card
        sharedSecret = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        Crypto.random.generateData(sharedSecret, (short)0, (short)32);
        iv = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        Crypto.random.generateData(iv, (short)0, (short)16);
        // temporary buffer for stuff
        tempBuffer = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);

        sharedKey = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        ((AESKey)sharedKey).setKey(sharedSecret, (short)0);
    }
    static public ECPublicKey getPubkey(){
        return (ECPublicKey)uniqueKeyPair.getPublic();
    }
    static public void establishSharedSecret(byte[] buf, short offset){
        Secp256k1.ecdh((ECPrivateKey)uniqueKeyPair.getPrivate(), 
                        buf, offset, (short)65, 
                        sharedSecret, (short)0);
        ((AESKey)sharedKey).setKey(sharedSecret, (short)0);
    }
    static public short getSharedHash(byte[] buf, short offset){
        // sending sha256 of the shared secret
        Crypto.sha256.reset();
        Crypto.sha256.doFinal(sharedSecret, (short)0, (short)32, buf, offset);
        return (short)32;
    }
    static public short encrypt(byte[] data, short offset, short dataLen, byte[] cyphertext, short ctOffset){
        // TODO: check length
        Crypto.random.generateData(iv, (short)0, (short)16);
        Crypto.cipher.init(sharedKey, Cipher.MODE_ENCRYPT, iv, (short)0, (short)16);
        short len = Crypto.cipher.doFinal(data, offset, dataLen, tempBuffer, (short)0);
        Util.arrayCopyNonAtomic(iv, (short)0, cyphertext, ctOffset, (short)16);
        Util.arrayCopyNonAtomic(tempBuffer, (short)0, cyphertext, (short)(ctOffset+16), len);
        len += 16;
        Crypto.hmac_sha256.init(sharedSecret, (short)0, (short)32);
        len += Crypto.hmac_sha256.doFinal(cyphertext, ctOffset, len, cyphertext, (short)(ctOffset+len));
        return len;
    }
    // TODO: .sign() - signs arbitrary data with unique keypair
    // AFAIK signing process is deterministic so this method
    // can be used for anti-phishing words generation
    // like ColdCard's double-PIN technique
    // Recommended to hash incoming data with a prefix,
    // for example "KeyCheck" to narrow down signing
    // to a particular action
    static public short sign(){
        return 0;
    }
}