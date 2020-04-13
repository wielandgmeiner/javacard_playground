/* Do what the fuck you want license. */
package toys;

import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: TransientStack.java 
 * Class: TransientStack
 */
// should it be called TransientHeap instead?
// it kinda operates as a stack, but...
public class TransientStack{
    public byte[] buffer;
    private short[] cur;

    public TransientStack(short maxSize){
        // if maxSize < 0 -> throw error
        buffer = JCSystem.makeTransientByteArray(maxSize, JCSystem.CLEAR_ON_DESELECT);
        // because we want to keep it in RAM
        cur = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        cur[(short)0] = (short)0;
    }
    /**
     * @return length of the data
     */
    public short length(){
        return (short)buffer.length;
    }
    /**
     * @return number of free bytes that can be reserved
     */
    public short available(){
        return (short)(buffer.length-cur[(short)0]);
    }
    /**
     * @return number of bytes allocated on the stack
     */
    public short allocated(){
        return cur[(short)0];
    }
    /**
     * @return offset in the buffer
     */
    public short allocate(short size){
        if(size > available()){
            free();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        short offset = cur[(short)0];
        cur[(short)0] = (short)(offset+size);
        return offset;
    }
    /**
     * @return offset of the end of the stack
     */
    public short free(short size){
        if(size > cur[(short)0]){
            free();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        cur[(short)0] -= size;
        // fill with zeroes such that next function can be sure everything is zero
        Util.arrayFillNonAtomic(buffer, cur[(short)0], size, (byte)0x00);
        return cur[(short)0];
    }
    /**
     * Frees the whole stack
     * @return zero (offset of the end of the stack)
     */
    public short free(){
        Util.arrayFillNonAtomic(buffer, (short)0, (short)buffer.length, (byte)0x00);
        cur[(short)0] = (short)0;
        return (short)0;
    }
}