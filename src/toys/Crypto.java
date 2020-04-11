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
    static public void pbkdf2(TransientStack st,
                        byte[] pass, short pOff, short pLen,
                        byte[] salt, short sOff, short sLen,
                        short iterations,
                        byte[] out, short outOff){
        // put into RAM, it will slightly speed up calculations
        short blockSize = HMACDigest.ALG_SHA_512_BLOCK_SIZE;
        byte ipad = HMACDigest.IPAD;
        byte opad = HMACDigest.OPAD;
        MessageDigest hash = Crypto.sha512;
        hash.reset();
        // get temp buffer for ikey, okey and U
        short ikeyOff = st.allocate((short)(blockSize*2+64));
        if(ikeyOff < 0){
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        short okeyOff = (short)(ikeyOff+blockSize);
        short dataOff = (short)(okeyOff+blockSize);
        byte[] buf = st.buffer;

        if(pLen > blockSize) {
            hash.doFinal(pass, pOff, pLen, st.buffer, ikeyOff);
        }else{
            Util.arrayFillNonAtomic(buf, ikeyOff, blockSize, (byte)0);
            Util.arrayCopyNonAtomic(pass, pOff, buf, ikeyOff, pLen);
        }
        Util.arrayCopyNonAtomic(buf, ikeyOff, buf, okeyOff, blockSize);
        for(short i = (short)0; i < blockSize; i++) {
            buf[(short)(ikeyOff+i)] = (byte)(buf[(short)(ikeyOff+i)]^ipad);
            buf[(short)(okeyOff+i)] = (byte)(buf[(short)(okeyOff+i)]^opad);
        }
        // i = 1
        Util.arrayFillNonAtomic(buf, dataOff, (short)4, (byte)0);
        buf[(short)(dataOff+3)] = (byte)1;
        // U
        hash.update(buf, ikeyOff, blockSize);
        hash.update(salt, sOff, sLen);
        hash.doFinal(buf, dataOff, (short)4, buf, dataOff);
        hash.update(buf, okeyOff, blockSize);
        hash.doFinal(buf, dataOff, (short)64, buf, dataOff);

        Util.arrayCopyNonAtomic(buf, dataOff, out, outOff, (short)64);
        for(short j=(short)2; j<=iterations; j++){
            hash.update(buf, ikeyOff, blockSize);
            hash.doFinal(buf, dataOff, (short)64, buf, dataOff);
            hash.update(buf, okeyOff, blockSize);
            hash.doFinal(buf, dataOff, (short)64, buf, dataOff);
            for(short i = (short)0; i < (short)64; i++) {
                out[(short)(outOff+i)] = (byte)(out[(short)(outOff+i)]^buf[(short)(dataOff+i)]);
            }
        }
        // get our memory back
        st.free((short)(blockSize*2+64));
    }
}