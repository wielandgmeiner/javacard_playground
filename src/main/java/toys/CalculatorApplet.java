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
    // abusing RSA engine
    private static final byte INS_SQUARE_FP            = (byte)0xAB;
    private static final byte INS_CUBE_FP              = (byte)0xAC;
    private static final byte INS_INVERSE_FP           = (byte)0xAD;
    private static final byte INS_SQUARE_N             = (byte)0xAE;
    private static final byte INS_CUBE_N               = (byte)0xAF;
    private static final byte INS_INVERSE_N            = (byte)0xB0;
    // ecc again...
    private static final byte INS_COMPRESS             = (byte)0xB1;
    private static final byte INS_UNCOMPRESS           = (byte)0xB2;
    // fix S in signature
    private static final byte INS_FIX_SIGNATURE        = (byte)0xB3;

    private TransientHeap heap;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new CalculatorApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public CalculatorApplet(){
        // allocate some memory in RAM for intermediate calculations
        heap = new TransientHeap((short)1024);
        Secp256k1.init(heap);
        Crypto.init(heap);
        FiniteField.init(heap);
        Bitcoin.init(heap);
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

        // clean up the heap before we start
        heap.free();

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
            FiniteField.addMod(buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_FP, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_ADDMOD_N:
            // TODO: check that arguments are 32 byte long
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.addMod(buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_R, (short)0);
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
            short off = heap.allocate((short)32);
            // should be zero anyways, but just in case
            Util.arrayFillNonAtomic(heap.buffer, off, (short)32, (byte)0);
            heap.buffer[(short)(off+31)] = (byte)1;
            Secp256k1.tempPrivateKey.setS(heap.buffer, off, (short)32);
            // redeem the memory
            heap.free((short)32);
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
            Bitcoin.xprvChild(buf, (short)(offset+1), buf, (short)(offset+67), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        // <xpub><index><uncompressed pubkey>
        case INS_XPUB_CHILD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // TODO: check args len
            Bitcoin.xpubChild(
                      buf, (short)(offset+1), 
                      buf, (short)(offset+67), 
                      buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        case PBKDF2_HMAC_SHA512:
            if(numElements != 3){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short iterations = Util.getShort(buf, (short)(offset+1));
            Crypto.pbkdf2(
                   buf, (short)(offset+4), buf[(short)(offset+3)], 
                   buf, (short)(offset+5+buf[(short)(offset+3)]), buf[(short)(offset+4+buf[(short)(offset+3)])], 
                   iterations,
                   buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        case INS_SQUARE_FP:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.powShortModFP(buf, (short)(offset+1), (short)2, buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_CUBE_FP:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.powShortModFP(buf, (short)(offset+1), (short)3, buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_INVERSE_FP:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.powShortModFP(buf, (short)(offset+1), (short)(-1), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_SQUARE_N:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.powShortModN(buf, (short)(offset+1), (short)2, buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_CUBE_N:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.powShortModN(buf, (short)(offset+1), (short)3, buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_INVERSE_N:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            FiniteField.powShortModN(buf, (short)(offset+1), (short)(-1), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_COMPRESS:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Secp256k1.compress(buf, (short)(offset+1), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)33);
            break;
        case INS_UNCOMPRESS:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Secp256k1.uncompress(buf, (short)(offset+1), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        case INS_FIX_SIGNATURE:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short delta = Secp256k1.setLowS(buf, (short)(offset+1));
            buf[offset] += delta;
            apdu.setOutgoingAndSend((short)0, (short)(buf[offset]+1+offset));
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
            offset += Util.makeShort((byte)0, buf[offset]);
            offset++;
            numElements++;
        }
        if(offset > end){
            return -1;
        }
        return numElements;
    }
}
