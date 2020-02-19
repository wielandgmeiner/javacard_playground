// define package name.
package toys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: toys
 * Filename: DataEntry.java 
 * Class: DataEntry
 */
public class DataEntry{
    private byte[] buffer;
    private short bufferLength = (short)0;
    private short bufferMaxLength = (short)0;

    public DataEntry(short maxSize){
        // if maxSize < 0 -> throw error
        bufferMaxLength = maxSize;
        buffer = new byte[maxSize];
    }
    public short put(byte[] data, short offset, short len){
        if(len > bufferMaxLength){
            return 0;
        }
        wipe();
        bufferLength = (short)0;
        Util.arrayCopy(data, offset, buffer, (short)0, len);
        bufferLength = len;
        return bufferLength;
    }
    public byte[] get(){
        return buffer;
    }
    public short length(){
        return bufferLength;
    }
    public short maxLength(){
        return bufferMaxLength;
    }
    public void wipe(){
        byte[] randombuffer = new byte[bufferMaxLength];
        Util.arrayCopy(randombuffer, (short)0, buffer, (short)0, bufferMaxLength);
    }
}