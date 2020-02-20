// define package name.
package toys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: toys
 * Filename: MemoryCardApplet.java 
 * Class: MemoryCardApplet
 */
public class MemoryCardApplet extends TeapotApplet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    protected static final byte CLA_MEMORYCARD            = (byte)0xB1;

    // Challenge management - to detect swapping of the card
    // We limit number of challenges to avoid sweep
    protected static final byte INS_CHALLENGE_GET_COUNTER = (byte)0x10;
    // does HMAC-SHA256(challenge, challenge_secret) with internal secret
    protected static final byte INS_HMAC_CHALLENGE        = (byte)0x11;

    // PIN management. Not according to ISO 7816-4. Should we care?
    protected final static short SW_WRONG_PIN = (short) 0x63c0;
    // try to unlock with the PIN
    protected static final byte INS_PIN_VERIFY            = (byte)0x20;
    // get PIN counter - returns max counter value and attempts left
    // PIN counter should be decrementing and boundary checked
    // Using built-in OwnerPIN for now.
    protected static final byte INS_PIN_GET_COUNTER       = (byte)0x21;
    // set PIN for uninitialized or change for unlocked card
    protected static final byte INS_PIN_SET               = (byte)0x22;
    // lock the card
    protected static final byte INS_LOCK                  = (byte)0x23;
    // get card status - locked or not
    protected static final byte INS_IS_LOCKED             = (byte)0x24;

    // from TEAPOT class, with CLA_MEMORYCARD available only when unlocked
    // protected static final byte INS_GET                  = (byte)0xA1;
    // protected static final byte INS_PUT                  = (byte)0xA2;

    protected static final byte PIN_MAX_LENGTH = (byte)32;
    protected static final byte PIN_MAX_COUNTER = (byte)10;

    protected OwnerPIN pin = null;
    protected DataEntry secretData = null;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public MemoryCardApplet(){
        // Teapot will take care of data initialization
        super();
        // Replace default data for MemoryCard
        byte[] defaultData = { 
            'M', 'e', 'm', 'o', 'r', 'y', ' ', 'c', 
            'a', 'r', 'd', 's', ' ', 'a', 'r', 'e', 
            ' ', 'n', 'o', 't', ' ', 's', 'a', 'f', 
            'u' 
        };
        data.put(defaultData, (short)0, (short)defaultData.length);

        if (secretData == null){
            secretData = new DataEntry(MAX_DATA_LENGTH);
        }
        secretData.put(defaultData, (short)0, (short)defaultData.length);
    }
}