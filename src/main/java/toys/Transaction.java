package toys;

import javacard.framework.Util;
import javacard.security.MessageDigest;

/* 
 * Package: toys
 * Filename: Transaction.java 
 * Class: Transaction
 */
public class Transaction{
    // Note: we only support segwit transactions
    final public  static short STATE_OFFSET          = (short)0;
    final private static short VERSION_OFFSET        = (short)1;
    final private static short HASH_PREVOUTS_OFFSET  = (short)5;
    final private static short HASH_SEQUENCES_OFFSET = (short)37;
    final private static short HASH_OUTPUTS_OFFSET   = (short)69;
    final private static short LOCKTIME_OFFSET       = (short)101;

    final public  static short LEN_CONTEXT           = (short)105;
    final public  static short LEN_VERSION           = (short)4;
    final public  static short LEN_SEQUENCE          = (short)4;
    final public  static short LEN_PREVOUT           = (short)36;
    final public  static short LEN_LOCKTIME          = (short)4;
    final public  static short LEN_SIGHASH           = (short)4;

    final private static byte STATE_UNDEFINED       = (byte)0;
    final private static byte STATE_PREVOUTS        = (byte)2;
    final private static byte STATE_SEQUENCES       = (byte)3;
    final private static byte STATE_OUTPUTS         = (byte)4;
    final private static byte STATE_READY           = (byte)5;
    final private static byte STATE_SIGHASH         = (byte)6;

    private byte[] ctx;
    private short ctxOff;
    // we need our own sha256 context 
    // because we hash in pieces, so it has to be
    // in sync with current tx state
    private MessageDigest sha256;
    /*
     * Context should be 105 bytes long
     * We store all offsets in a transient array
     * because there is no way to save hash state
     */
    public Transaction(TransientHeap hp, byte[] context, short contextOff){
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        ctx = context;
        ctxOff = contextOff;
    }
    public void setVersion(byte[] ver, short verOff){
        finishState();
        Util.arrayCopyNonAtomic(ver, verOff, 
                ctx, (short)(ctxOff+VERSION_OFFSET), 
                LEN_VERSION);
        setState(STATE_READY);
    }
    public void addPrevout(byte[] prevout, short off){
        if(getState()!=STATE_PREVOUTS){
            finishState();
            setState(STATE_PREVOUTS);
        }
        sha256.update(prevout, off, LEN_PREVOUT);
    }
    public void addSequence(byte[] sequence, short off){
        if(getState()!=STATE_SEQUENCES){
            finishState();
            setState(STATE_SEQUENCES);
        }
        sha256.update(sequence, off, LEN_SEQUENCE);
    }
    public void addOutput(byte[] out, short off, short len){
        if(getState()!=STATE_OUTPUTS){
            finishState();
            setState(STATE_OUTPUTS);
        }
        sha256.update(out, off, len);
    }
    public void setLocktime(byte[] locktime, short locktimeOff){
        finishState();
        Util.arrayCopyNonAtomic(locktime, locktimeOff, 
                ctx, (short)(ctxOff+LOCKTIME_OFFSET), 
                LEN_LOCKTIME);
        setState(STATE_READY);
    }
    // input data: txid, vout, script_pubkey, value, sequence
    // may be a part of it
    public void startSighash(){
        finishState();
        // version
        sha256.update(ctx, (short)(ctxOff+VERSION_OFFSET), LEN_VERSION);
        // prevouts
        sha256.update(ctx, (short)(ctxOff+HASH_PREVOUTS_OFFSET), (short)32);
        // sequences
        sha256.update(ctx, (short)(ctxOff+HASH_SEQUENCES_OFFSET), (short)32);
        setState(STATE_SIGHASH);
    }
    public void updateSighash(byte[] data, short off, short len){
        if(getState()!=STATE_SIGHASH){
            startSighash();
        }
        sha256.update(data, off, len);
    }
    public short finishSighash(byte[] data, short off, short len,
                              byte[] sighash, short sighashOff,
                              byte[] out, short outOff){
        if(getState()!=STATE_SIGHASH){
            startSighash();
        }
        sha256.update(data, off, len);
        // outputs
        sha256.update(ctx, (short)(ctxOff+HASH_OUTPUTS_OFFSET), (short)32);
        // locktime
        sha256.update(ctx, (short)(ctxOff+LOCKTIME_OFFSET), LEN_LOCKTIME);
        // sighash
        sha256.doFinal(sighash, sighashOff, LEN_SIGHASH, out, outOff);
        // double sha
        sha256.doFinal(out, outOff, (short)32, out, outOff);
        return (short)32;
    }
    public void reset(){
        // clear context, reset sha and state
        Util.arrayFillNonAtomic(ctx, ctxOff, LEN_CONTEXT, (byte)0x00);
        sha256.reset();
        setState(STATE_UNDEFINED);
    }
    private void finishState(){
        byte state = getState();
        switch(state){
            case STATE_SEQUENCES:
                sha256.doFinal(ctx, ctxOff, (short)0,
                              ctx, (short)(ctxOff+HASH_SEQUENCES_OFFSET));
                // double sha
                sha256.doFinal(
                        ctx, (short)(ctxOff+HASH_SEQUENCES_OFFSET), (short)32,
                        ctx, (short)(ctxOff+HASH_SEQUENCES_OFFSET));
                break;
            case STATE_PREVOUTS:
                sha256.doFinal(ctx, ctxOff, (short)0,
                              ctx, (short)(ctxOff+HASH_PREVOUTS_OFFSET));
                // double sha
                sha256.doFinal(
                        ctx, (short)(ctxOff+HASH_PREVOUTS_OFFSET), (short)32,
                        ctx, (short)(ctxOff+HASH_PREVOUTS_OFFSET));
                break;
            case STATE_OUTPUTS:
                sha256.doFinal(ctx, ctxOff, (short)0,
                              ctx, (short)(ctxOff+HASH_OUTPUTS_OFFSET));
                // double sha
                sha256.doFinal(
                        ctx, (short)(ctxOff+HASH_OUTPUTS_OFFSET), (short)32,
                        ctx, (short)(ctxOff+HASH_OUTPUTS_OFFSET));
                break;
            default:
                sha256.reset();
        }
        setState(STATE_READY);
    }
    private void setState(byte state){
        ctx[(short)(ctxOff+STATE_OFFSET)] = state;
    }
    private byte getState(){
        return ctx[(short)(ctxOff+STATE_OFFSET)];
    }
}