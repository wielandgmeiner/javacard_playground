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
    static private RSAPublicKey rsaModFP;
    static private RSAPublicKey rsaModN;
    static private TransientHeap heap;
    static final private byte[] RSA_FP = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    static final private byte[] RSA_N = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    static public void init(TransientHeap hp){
        heap = hp;
        rsaModFP = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaModN = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        rsaModFP.setModulus(RSA_FP, (short)0, (short)64);
        rsaModN.setModulus(RSA_N, (short)0, (short)64);
    }
    // exponentiation modulo FP with short exponent (like 3 or -1)
    static public void powShortModFP(byte[] a, short aOff,
                                     short exponent,
                                     byte[] out, short outOff){
        powShortMod(a, aOff, exponent, out, outOff, rsaModFP, RSA_FP, (short)32);
    }
    // exponentiation modulo FP
    static public void powModFP(byte[] a, short aOff,
                                byte[] exp, short expOff, 
                                byte[] out, short outOff){
        powMod(a, aOff, exp, expOff, out, outOff, rsaModFP);
    }
    // exponentiation modulo N with short exponent (like 3 or -1)
    static public void powShortModN(byte[] a, short aOff,
                                    short exponent,
                                    byte[] out, short outOff){
        powShortMod(a, aOff, exponent, out, outOff, rsaModN, RSA_N, (short)32);
    }
    // exponentiation modulo N
    static public void powModN(byte[] a, short aOff,
                               byte[] exp, short expOff, 
                               byte[] out, short outOff){
        powMod(a, aOff, exp, expOff, out, outOff, rsaModN);
    }
    static public void powShortMod(byte[] a, short aOff,
                                   short exponent,
                                   byte[] out, short outOff, 
                                   RSAPublicKey rsaKey,
                                   byte[] mod, short modOff){    
        short len = (short)32;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // set 32-byte exponent
        if(exponent > 0){ // positive
            Util.setShort(buf, (short)(off+30), exponent);
        }else{ // negative
            exponent--; // n^(p-1)=1
            Util.setShort(buf, (short)(off+30), (short)(-exponent));
            subtract(mod, modOff, buf, off, buf, off, (short)1);
        }
        powMod(a, aOff, buf, off, out, outOff, rsaKey);
        heap.free(len);
    }
    // exponentiation modulo 
    static public void powMod(byte[] a, short aOff,
                              byte[] exp, short expOff, 
                              byte[] out, short outOff,
                              RSAPublicKey rsaKey){
        short len = (short)64;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;

        Util.arrayCopyNonAtomic(a, aOff, buf, (short)(off+32), (short)32);
        rsaKey.setExponent(exp, expOff, (short)32);
        rsaCipher.init(rsaKey, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(buf, off, (short)64, buf, off);
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        heap.free(len);
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
    static public void addMod(byte[] a,     short aOff, 
                              byte[] b,     short bOff, 
                              byte[] out,   short outOff, 
                              byte[] mod,   short modOff){
        short len = (short)32;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;
        // addition with carry
        short carry = add(a, aOff, b, bOff, buf, off);
        // carry will be 1 only if we got it from addition or
        // if result is larger than modulo
        carry += isGreaterOrEqual(buf, off, mod, modOff);
        // subtract in any case and store result in output buffer
        subtract(buf, off, mod, modOff, out, outOff, carry);
        heap.free(len);
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
    // TODO: make private. Create a public function that uses stack
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
    // TODO: make private. Create a public function that uses stack
    // TODO: implement public subtractMod function
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
    // TODO: implement mulModFP & mulModN
    // hint: 4*a*b = (a+b)^2-(a-b)^2
}