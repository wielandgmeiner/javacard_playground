package toys;

import javacard.framework.Util;

/**
 * A class to store variable length data in EEPROM.
 * In the constructor define the maximum capacity 
 * that will be allocated for storage.
 * <p>
 * Constructor is called with a single parameter - maximum capacity.
 * <pre>
 * // Usage example
 * DataEntry de = new DataEntry(maxLen); // create DataEntry with max capacity of maxLen
 * de.put(data, offset, len); // store data in the storage
 * byte[] buf = de.get();    // access bytearray of the storage,
 * short len = de.length();  // figure out the length of data stored,
 * short maxLen = de.maxLength(); // find maximum capacity of the storage
 * </pre>
 */
public class DataEntry{
    /** Byte buffer to store data in. Allocated in the constructor */
    private byte[] buffer;
    /** Length of the data currently stored */
    private short bufferLength = (short)0;
    /** Maximum length of the data we can store. Defined in the constructor. */
    private short bufferMaxLength = (short)0;

    /**
     * Class constructor. Allocates enough memory in EEPROM to store data.
     * @param maxSize - size that will be allocated for storage. 
     *                  Defines the maximum length of the data that we can store.
     */
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
     * @return length of the data currently stored
     */
    public short length(){
        return bufferLength;
    }
    /**
     * @return maximum length of the data that can be stored in this class 
     *         (internal buffer capacity)
     */
    public short maxLength(){
        return bufferMaxLength;
    }
    /**
     * Overwrites the content of the internal buffer with zeroes
     */
    public void wipe(){
        Util.arrayFillNonAtomic(buffer, (short)0, bufferMaxLength, (byte)0x00);
    }
}