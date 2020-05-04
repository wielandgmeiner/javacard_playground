/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: toys
 * Filename: TeapotApplet.java 
 * Class: TeapotApplet
 */
public class TeapotApplet extends Applet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    private static final byte CLA_TEAPOT               = (byte)0xB0;
    // Get data from the card 
    private static final byte INS_GET                  = (byte)0xA1;
    // Put data to the card (update)
    private static final byte INS_PUT                  = (byte)0xA2;
    // Max storage
    private static final short MAX_DATA_LENGTH         = (short)255;

    // Default data
    private DataEntry data = null;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new TeapotApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public TeapotApplet(){
        
        data = new DataEntry(MAX_DATA_LENGTH);
        byte[] defaultData = { 
            'I', ' ', 'a', 'm', ' ', 'a', ' ', 't', 
            'e', 'a', 'p', 'o', 't', ' ', 'g', 'i', 
            'm', 'm', 'e', ' ', 's', 'o', 'm', 'e', 
            ' ', 't', 'e', 'a', ' ', 'p', 'l', 'z' 
        };
        data.put(defaultData, (short)0, (short)defaultData.length);
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
        if(buf[ISO7816.OFFSET_CLA] != CLA_TEAPOT){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // Dispatch INS in APDU.
        switch (buf[ISO7816.OFFSET_INS]){
        case INS_GET:
            // The APDU format can be "B0 A1 P1 P2 Lc Data Le", 
            // such as "B0A10000" or "B0A101020311223300".
            SendData(apdu);
            break;

        case INS_PUT:
            // The APDU format can be "B0 A2 P1 P2 Lc Data Le",
            // such as "B0A2000002112200".
            // Up to 32 bytes
            StoreData(apdu);
            break;

        default:
            // If you don't know the INS, throw an exception.
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * Stores data on the card and then sends updated data as a responce
     * @param apdu the APDU buffer
     */
    private void StoreData(APDU apdu){
        byte[] buf = apdu.getBuffer();
        short len = Util.makeShort((byte)0, buf[ISO7816.OFFSET_LC]);
        // check if data length is ok
        if(len > MAX_DATA_LENGTH){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // copy content of the buffer to the data array
        data.put(buf, (short)ISO7816.OFFSET_CDATA, len);
        SendData(apdu);
    }

    /**
     * Sends data from the card in APDU responce
     * @param apdu the APDU buffer
     */
    private void SendData(APDU apdu){
        apdu.setOutgoing();
        apdu.setOutgoingLength(data.length());
        apdu.sendBytesLong(data.get(), (short)0, data.length());
    }

}
