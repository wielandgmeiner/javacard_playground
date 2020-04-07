/* Do what the fuck you want license. */
package toys;

/*
 * All instances of crypto primitives are here.
 * Call .init() once in the applet
 * All functions are static, so can be used in other classes
 * This approach saves RAM
 */

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/* 
 * Package: toys
 * Filename: Crypto.java 
 * Class: Crypto
 */
public class Crypto{
    static public RandomData random;
    static public MessageDigest sha256;
    static public MessageDigest sha512;
    static public HMACDigest hmacSha256;
    static public HMACDigest hmacSha512;
    static public Cipher cipher;

    static public void init(){
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        hmacSha256 = new HMACDigest(sha256, HMACDigest.ALG_SHA_256_BLOCK_SIZE);
        hmacSha512 = new HMACDigest(sha512, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);
    }
}