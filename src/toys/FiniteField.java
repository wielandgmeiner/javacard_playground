/* Do what the fuck you want license. */
package toys;

import javacard.framework.*;

/* 
 * Package: toys
 * Filename: FinalField.java 
 * Class: FinalField
 */
public class FiniteField{
    // constant time modulo addition
    // can tweak in place
    static public void addMod(TransientStack st,
                        byte[] a,     short aOff, 
                        byte[] b,     short bOff, 
                        byte[] out,   short outOff, 
                        byte[] mod,   short modOff){
        short off = st.allocate((short)32);
        if(off < 0){
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
        st.free((short)32);
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
    static private short add(byte[] a, short aOff,
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
    static private short subtract(byte[] a, short aOff, 
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