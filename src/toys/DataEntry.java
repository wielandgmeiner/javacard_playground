/* Do what the fuck you want license. */
package toys;

import javacard.framework.*;
import javacard.security.*;

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
    /**
     * Stores data on the card and then sends updated data as a responce
     * @param data   - byte array with data to store
     * @param offset - start position of the data in the buffer
     * @param len    - length of the data
     * @return number of bytes stored. Should be equal to len. 0 if data is too large.
     */
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
    /**
     * @return internal buffer with the data
     */
    public byte[] get(){
        return buffer;
    }
    /**
     * @return length of the data
     */
    public short length(){
        return bufferLength;
    }
    /**
     * @return buffer capacity
     */
    public short maxLength(){
        return bufferMaxLength;
    }
    /**
     * Erases content of the data with random junk
     */
    public void wipe(){
        Util.arrayFillNonAtomic(buffer, (short)0, bufferMaxLength, (byte)0x00);
    }
}