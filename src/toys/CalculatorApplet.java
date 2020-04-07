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
