package toys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: toys
 * Filename: MemoryCardApplet.java 
 * Class: MemoryCardApplet
 */
public class MemoryCardApplet extends SecureApplet{

    // Max storage
    private static final short MAX_DATA_LENGTH         = (short)255;

    // commands transmitted over secure channel
    // 0x00 - 0x04 are reserved
    private static final byte CMD_STORAGE             = (byte)0x05;
    // storage
    private static final byte SUBCMD_STORAGE_GET      = (byte)0x00;
    private static final byte SUBCMD_STORAGE_PUT      = (byte)0x01;

    private DataEntry secretData;

    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new MemoryCardApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);;
    }
    public MemoryCardApplet(){
        super();

        // Default data
        byte[] defaultData = { 
            'M', 'e', 'm', 'o', 'r', 'y', ' ', 'c', 
            'a', 'r', 'd', 's', ' ', 'a', 'r', 'e', 
            ' ', 'n', 'o', 't', ' ', 's', 'a', 'f', 
            'u', ' ', 's', 'o', ' ', 'w', 'h', 'a',
            't', '?'
        };
        secretData = new DataEntry(MAX_DATA_LENGTH);
        secretData.put(defaultData, (short)0, (short)defaultData.length);
    }
    protected short processSecureMessage(byte[] buf, short offset, short len){
        if(buf[offset] == CMD_STORAGE){
            return processStorageCommand(buf, offset, len);
        }else{
            ISOException.throwIt(ERR_INVALID_CMD);
        }
        return (short)2;
    }
    protected short processPlainMessage(byte[] msg, short msgOff, short msgLen){
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return (short)0;
    }
    private short processStorageCommand(byte[] buf, short offset, short len){
        if(isLocked()){
            ISOException.throwIt(ERR_CARD_LOCKED);
            return (short)2;
        }
        byte subcmd = buf[(short)(offset+1)];
        buf[offset] = (byte)0x90;
        buf[(short)(offset+1)] = (byte)0x00;
        switch (subcmd){
            case SUBCMD_STORAGE_GET:
                Util.arrayCopyNonAtomic(secretData.get(), (short)0, buf, (short)(offset+2), secretData.length());
                return (short)(2+secretData.length());
            case SUBCMD_STORAGE_PUT:
                secretData.put(buf, (short)2, (short)(len-2));
                return (short)2;
            default:
                ISOException.throwIt(ERR_INVALID_SUBCMD);
        }
        return (short)2;
    }
}