/* Do what the fuck you want license. */
package toys;

import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;

/* 
 * Package: toys
 * Filename: FinalField.java 
 * Class: FinalField
 */
public class FiniteField{
    static private Cipher rsaCipher;
    static private RSAPublicKey rsaPubkey;
    static final private byte[] FP2 = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFD,(byte)0xFF,(byte)0xFF,(byte)0xF8,(byte)0x5E,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x07,(byte)0xA2,(byte)0x00,(byte)0x0E,(byte)0x90,(byte)0xA1
    };
    static final private byte[] FP = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    static public void init(){
        rsaPubkey = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        rsaPubkey.setModulus(FP, (short) 0x00, (short)64);
    }
    // exponentiation modulo FP with short exponent (like 3 or -1)
    static public void powShortModFP(TransientStack st,
                            byte[] a, short aOff,
                            short exponent,
                            byte[] out, short outOff){
        short len = (short)32;
        short off = st.allocate(len);
        byte[] buf = st.buffer;
        if(off < 0){ // failed to allocate memory
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        // set 32-byte exponent
        if(exponent > 0){ // positive
            Util.setShort(buf, (short)(off+30), exponent);
        }else{ // negative
            exponent--; // n^(FP-1)=1
            Util.setShort(buf, (short)(off+30), (short)(-exponent));
            subtract(Secp256k1.SECP256K1_FP, (short)0, buf, off, buf, off, (short)1);
        }
        powModFP(st, a, aOff, buf, off, out, outOff);
        st.free(len);
    }
    // exponentiation modulo FP
    static public void powModFP(TransientStack st, 
                            byte[] a, short aOff,
                            byte[] exp, short expOff, 
                            byte[] out, short outOff){
        short len = (short)64;
        short off = st.allocate(len);
        byte[] buf = st.buffer;
        if(off < 0){ // failed to allocate memory
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        Util.arrayCopyNonAtomic(a, aOff, buf, (short)(off+32), (short)32);
        rsaPubkey.setExponent(exp, expOff, (short)32);
        rsaCipher.init(rsaPubkey, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(buf, off, (short)64, buf, off);
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        st.free(len);
    }
    // get random number up to max value
    // max should be large enough as we are just trying over and over
    // until we get correct number
    static public void getRandomElement(byte[] max, short maxOff,
                                        byte[] out, short outOff){
        Crypto.random.generateData(out, outOff, (short)32);
        while(isGreaterOrEqual(out, outOff, max, maxOff) > 0){
            Crypto.random.generateData(out, outOff, (short)32);
        }
    }
    // constant time modulo addition
    // can tweak in place
    static public void addMod(TransientStack st,
                        byte[] a,     short aOff, 
                        byte[] b,     short bOff, 
                        byte[] out,   short outOff, 
                        byte[] mod,   short modOff){
        short len = (short)32;
        short off = st.allocate(len);
        if(off < 0){ // failed to allocate memory
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        byte[] buf = st.buffer;
        // addition with carry
        short carry = add(a, aOff, b, bOff, buf, off);
        // carry will be 1 only if we got it from addition or
        // if result is larger than modulo
        carry += isGreaterOrEqual(buf, off, mod, modOff);
        // subtract in any case and store result in output buffer
        subtract(buf, off, mod, modOff, out, outOff, carry);
        st.free(len);
    }
    // constant time comparison
    static public short isGreaterOrEqual(byte[] a, short aOff,
                                   byte[] b, short bOff){
        // if a is smaller than b, a-b will be negative
        // and we will get carry of -1
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((a[(short)(aOff+i)]&0xFF)-(b[(short)(bOff+i)]&0xFF)+carry);
            carry = (short)(carry>>8);
        }
        return (short)(1+carry);
    }
    // addition of two 256-bit numbers, returns carry
    // WARNING: can't do subtraction in place with different offsets
    // output buffer should be a different one, 
    // use temp buffer for example
    static public short add(byte[] a, short aOff,
                      byte[] b, short bOff,
                      byte[] out, short outOff){
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((short)(a[(short)(aOff+i)]&0xFF)+(short)(b[(short)(bOff+i)]&0xFF)+carry);
            out[(short)(outOff+i)] = (byte)carry;
            carry = (short)(carry>>8);
        }
        return carry;
    }
    // subtraction of two 256-bit numbers, returns carry
    // WARNING: can't do subtraction in place with different offsets
    // output buffer should be a different one, 
    // use temp buffer for example
    static public short subtract(byte[] a, short aOff, 
                     byte[] b, short bOff,
                     byte[] out, short outOff, 
                     short multiplier){
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((a[(short)(aOff+i)]&0xFF)-(b[(short)(bOff+i)]&0xFF)*multiplier+carry);
            out[(short)(outOff+i)] = (byte)carry;
            carry = (short)(carry>>8);
        }
        return carry;
    }
}