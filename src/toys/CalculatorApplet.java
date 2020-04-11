/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: CalculatorApplet.java 
 * Class: CalculatorApplet
 */
public class CalculatorApplet extends Applet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    private static final byte CLA_CALC                 = (byte)0xB0;

    private static final byte PBKDF2_HMAC_SHA512       = (byte)0xA0;
    private static final byte INS_SHA256               = (byte)0xA1;
    private static final byte INS_HMAC_SHA256          = (byte)0xA2;
    private static final byte INS_SHA512               = (byte)0xA3;
    private static final byte INS_HMAC_SHA512          = (byte)0xA4;
    // finite field math
    private static final byte INS_ADDMOD_FP            = (byte)0xA5;
    private static final byte INS_ADDMOD_N             = (byte)0xA6;
    // ecc
    private static final byte INS_ECC_TWEAK_ADD        = (byte)0xA7;
    private static final byte INS_ECC_ADD              = (byte)0xA8;
    // bip32
    private static final byte INS_XPRV_CHILD           = (byte)0xA9;
    private static final byte INS_XPUB_CHILD           = (byte)0xAA;

    private TransientStack stack;

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
        // allocate some memory in RAM for intermediate calculations
        stack = new TransientStack((short)512);
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

        // clean up the stack before we start
        stack.free();

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
            FiniteField.addMod(stack, buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_FP, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_ADDMOD_N:
            // TODO: check that arguments are 32 byte long
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.addMod(stack, buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_R, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_ECC_TWEAK_ADD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Secp256k1.tempPrivateKey.setS(buf, (short)(offset+1), (short)32);
            Secp256k1.tweakAdd(Secp256k1.tempPrivateKey, 
                               buf, (short)(offset+34), (short)65, 
                               buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        case INS_ECC_ADD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short off = stack.allocate((short)32);
            if(off < 0){ // failed to allocate
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            // should be zero anyways, but just in case
            Util.arrayFillNonAtomic(stack.buffer, off, (short)32, (byte)0);
            stack.buffer[(short)(off+31)] = (byte)1;
            Secp256k1.tempPrivateKey.setS(stack.buffer, off, (short)32);
            // redeem the memory
            stack.free((short)32);
            // set G to our point
            Secp256k1.tempPrivateKey.setG(buf, (short)(offset+1), (short)65);
            Secp256k1.tweakAdd(Secp256k1.tempPrivateKey, 
                               buf, (short)(offset+67), (short)65, 
                               buf, (short)0);
            // set G back to normal
            Secp256k1.tempPrivateKey.setG(Secp256k1.SECP256K1_G, (short)0, (short)65);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        // <xprv><index>
        case INS_XPRV_CHILD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // TODO: check args len
            Bitcoin.xprvChild(stack, buf, (short)(offset+1), buf, (short)(offset+67), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        // <xpub><index><uncompressed pubkey>
        case INS_XPUB_CHILD:
            if(numElements != 3){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // TODO: check args len
            Bitcoin.xpubChild(stack, 
                      buf, (short)(offset+1), 
                      buf, (short)(offset+67), 
                      buf, (short)(offset+67+5), 
                      buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        case PBKDF2_HMAC_SHA512:
            if(numElements != 3){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short iterations = Util.getShort(buf, (short)(offset+1));
            Crypto.pbkdf2(stack, // for temporary allocations
                   buf, (short)(offset+4), buf[(short)(offset+3)], 
                   buf, (short)(offset+5+buf[(short)(offset+3)]), buf[(short)(offset+4+buf[(short)(offset+3)])], 
                   iterations,
                   buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        default:
            // If you don't know the INS, throw an exception.
            buf[0] = numElements;
            apdu.setOutgoingAndSend((short)0, (short)1);
            // ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
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
