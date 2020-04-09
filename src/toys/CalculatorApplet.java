/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: toys
 * Filename: CalculatorApplet.java 
 * Class: CalculatorApplet
 */
public class CalculatorApplet extends Applet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    private static final byte CLA_CALC                 = (byte)0xB0;

    private static final byte INS_SHA256               = (byte)0xA1;
    private static final byte INS_HMAC_SHA256          = (byte)0xA2;
    private static final byte INS_SHA512               = (byte)0xA3;
    private static final byte INS_HMAC_SHA512          = (byte)0xA4;
    // finite field math
    private static final byte INS_ADDMOD_FP            = (byte)0xA5;
    private static final byte INS_ADDMOD_N             = (byte)0xA6;

    private byte[] scratch;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new CalculatorApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public CalculatorApplet(){
        Secp256k1.init();
        Crypto.init();
        scratch = new byte[32];
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
        // Get the APDU buffer byte array.
        byte[] buf = apdu.getBuffer();
        // Calling this method indicates that this APDU has incoming data. 
        apdu.setIncomingAndReceive();
        
        // If the CLA is not equal to 0xB0(CLA_TEAPOT),  throw an exception.
        if(buf[ISO7816.OFFSET_CLA] != CLA_CALC){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // check we have at least one element
        // and list is formed correctly
        short len = Util.makeShort((byte)0, buf[ISO7816.OFFSET_LC]);
        byte numElements = checkList(buf, (short)ISO7816.OFFSET_CDATA, len);
        // if(numElements < 1){
        //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // }
        // Dispatch INS in APDU.
        short offset = (short)ISO7816.OFFSET_CDATA;

        switch (buf[ISO7816.OFFSET_INS]){
        case INS_SHA256:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.sha256.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_SHA512:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.sha512.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        case INS_HMAC_SHA256:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.hmacSha256.init(buf, (short)(offset+1), buf[offset]);
            offset += (short)(buf[offset]+1);
            Crypto.hmacSha256.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_HMAC_SHA512:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.hmacSha512.init(buf, (short)(offset+1), buf[offset]);
            offset += (short)(buf[offset]+1);
            Crypto.hmacSha512.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        case INS_ADDMOD_FP:
            // TODO: check that arguments are 32 byte long
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            addMod(buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_FP, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_ADDMOD_N:
            // TODO: check that arguments are 32 byte long
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            addMod(buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_R, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        default:
            // If you don't know the INS, throw an exception.
            buf[0] = numElements;
            apdu.setOutgoingAndSend((short)0, (short)1);
            // ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    // constant time modulo addition
    private void addMod(byte[] a,     short aOff, 
                        byte[] b,     short bOff, 
                        byte[] out,   short outOff, 
                        byte[] prime, short pOff){
        // addition with carry
        short carry = add(a, aOff, b, bOff, scratch, (short)0);
        // subtract in any case and store result in output buffer
        short scarry = subtract(scratch, (short)0, prime, pOff, out, outOff);
        // check if we actually needed to subtract
        if(carry!=0 || scarry==0){
            // we are fine, but we need to copy something, 
            // so let's copy output buffer to temp buffer
            Util.arrayCopyNonAtomic(out, outOff, scratch, (short)0, (short)32);
        }else{
            // there was no overflow - copy from temp buffer to output
            Util.arrayCopyNonAtomic(scratch, (short)0, out, outOff, (short)32);
        }
    }
    // addition of two 256-bit numbers, returns carry
    // WARNING: can't do subtraction in place with different offsets
    // output buffer should be a different one, 
    // use temp buffer, scratch for example
    private short add(byte[] a, short aOff,
                      byte[] b, short bOff,
                      byte[] out, short outOff){
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((short)(a[(short)(aOff+i)]&0xFF)+(short)(b[(short)(bOff+i)]&0xFF)+carry);
            scratch[i] = (byte)carry;
            carry = (short)(carry>>8);
        }
        return carry;
    }
    // subtraction of two 256-bit numbers, returns carry
    // WARNING: can't do subtraction in place with different offsets
    // output buffer should be a different one, 
    // use temp buffer, scratch for example
    private short subtract(byte[] a, short aOff, 
                     byte[] b, short bOff,
                     byte[] out, short outOff){
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((a[(short)(aOff+i)]&0xFF)-(b[(short)(bOff+i)]&0xFF)-carry);
            out[(short)(outOff+i)] = (byte)carry;
            carry = (short)(((carry>>8)!=0) ? 1 : 0);
        }
        return carry;
    }
    // constant time comparison
    private boolean isGreater(byte[] a, short aOff,
                              byte[] b, short bOff){
        // if a more than b, b-a will be negative - we will get non-zero carry
        return (subtract(b, bOff, a, aOff, scratch, (short)0)!=0);
    }
    // checks that buffer contains a list of elements
    // encoded as <len><data><len><data>...
    // and returns number of elements
    // -1 if encoding is not correct
    private byte checkList(byte[] buf, short offset, short len){
        short end = (short)(offset+len);
        byte numElements = (byte)0;
        while(offset < end){
            offset += buf[offset];
            offset++;
            numElements++;
        }
        if(offset > end){
            return -1;
        }
        return numElements;
    }
}
