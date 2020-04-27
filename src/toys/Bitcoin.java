/* Do what the fuck you want license. */
package toys;

import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: Bitcoin.java 
 * Class: Bitcoin
 */
public class Bitcoin{
    static private TransientHeap heap;

    // 8*24+23 - max 24 words at most 8 characters each + spaces
    public static final short MAX_MNEMONIC_LENGTH      = (short)215;
    // 74 bytes, without prefix: 
    // depth, child index, parent fingerprint, chain code, pubkey
    public static final short SEED_LEN                 = (short)64;
    public static final short HDKEY_LEN                = (short)74;
    public static final short HDKEY_DEPTH_OFFSET       = (short)0;
    public static final short HDKEY_INDEX_OFFSET       = (short)1;
    public static final short HDKEY_FINGERPRINT_OFFSET = (short)5;
    public static final short HDKEY_CHAINCODE_OFFSET   = (short)9;
    public static final short HDKEY_FLAG_OFFSET        = (short)41;
    public static final short HDKEY_PUB_KEY_OFFSET     = (short)41;
    public static final short HDKEY_PRV_KEY_OFFSET     = (short)42;
    public static final byte[] HDKEY_SEED_KEY = {'B','i','t','c','o','i','n',' ','s','e','e','d'};

    static public void init(TransientHeap hp){
        heap = hp;
    }
    static public short xprvFromSeed(byte[] seed, short seedOff,
                                     byte[] out, short outOff){
        // set depth, child number and fingerprint to zero
        Util.arrayFillNonAtomic(out, outOff, HDKEY_LEN, (byte)0);
        short len = (short)64;
        short off = heap.allocate(len);
        // do hmac_sha512("Bitcoin seed", seed)
        Crypto.hmacSha512.init(HDKEY_SEED_KEY, (short)0, (short)(HDKEY_SEED_KEY.length));
        Crypto.hmacSha512.doFinal(seed, seedOff, SEED_LEN, heap.buffer, off);
        // copy first 32 bytes to private key
        Util.arrayCopyNonAtomic(
                    heap.buffer, off, 
                    out, (short)(outOff+HDKEY_PRV_KEY_OFFSET), 
                    (short)32);
        // copy last 32 bytes to chain code
        Util.arrayCopyNonAtomic(
                    heap.buffer, (short)(off+32), 
                    out, (short)(outOff+HDKEY_CHAINCODE_OFFSET), 
                    (short)32);
        heap.free(len);
        return HDKEY_LEN;
    }
    static public boolean bip32IsPrivate(byte[] hdKey, short hdOff){
        return (hdKey[(short)(hdOff+HDKEY_FLAG_OFFSET)]==(byte)0x00);
    }
    // takes a 74-byte xprv or xpub and derives
    // a child with derivation path der
    // each index is 4-byte long, 
    // derLen is length of derivation path in bytes, 
    // so if you are deriving m/44h/0h/0h derLen should be 12
    // if xpub is passed as an argument 
    // only non-hardened derivation is possible.
    // Output will be 74 bytes long: 
    // depth, child index, parent fingerprint, chain code, key
    static public short bip32Derive(byte[] hdKey, short hdOff,
                                    byte[] der, short derOff, short derLen,
                                    byte[] out, short outOff){
        boolean isPrivate = bip32IsPrivate(hdKey, hdOff);
        if((derLen % 4)!=0){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if(!isPrivate){
            for(short i=0; i<derLen; i+=4){
                if((der[(short)(derOff+i)]&0xFF)>=0x80){
                    // can't do hardened
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            }
        }
        // if derLen is 0 -> just copy
        if(derLen == (short)0){
            Util.arrayCopyNonAtomic(hdKey, hdOff, out, outOff, HDKEY_LEN);
            return HDKEY_LEN;
        }
        // fill depth
        out[outOff] = (byte)(hdKey[hdOff]+(derLen/4));
        // fill child index
        Util.arrayCopyNonAtomic(out, (short)(outOff+HDKEY_INDEX_OFFSET), der, (short)(derOff+derLen-4), (short)4);
        // derive
        short len = (short)(65+20);
        short off = heap.allocate(len);
        // copy to heap
        Util.arrayCopyNonAtomic(hdKey, (short)(hdOff+HDKEY_CHAINCODE_OFFSET), heap.buffer, off, (short)65);
        // derive all but the last one
        for(short i=0; i<(short)(derLen-4); i+=4){
            if(isPrivate){
                xprvChild(heap.buffer, off, 
                          der, (short)(derOff+i), 
                          heap.buffer, off);
            }else{
                xpubChild(heap.buffer, off, 
                          der, (short)(derOff+i), 
                          heap.buffer, off);
            }
        }
        // derive last one
        if(isPrivate){
            xprvChild(heap.buffer, off, 
                      der, (short)(derOff+derLen-4), 
                      out, (short)(outOff+HDKEY_CHAINCODE_OFFSET));
        }else{
            xpubChild(heap.buffer, off, 
                      der, (short)(derOff+derLen-4), 
                      out, (short)(outOff+HDKEY_CHAINCODE_OFFSET));
        }
        // fill parent fingerprint
        // if private - put public there instead
        if(isPrivate){
            Secp256k1.tempPrivateKey.setS(heap.buffer, (short)(off+33), (short)32);
            Secp256k1.pubkeyCreate(Secp256k1.tempPrivateKey, true, heap.buffer, (short)(off+HDKEY_PUB_KEY_OFFSET));
        }
        // calc hash160
        Crypto.hash160(heap.buffer, (short)(off+HDKEY_PUB_KEY_OFFSET), (short)33, 
                       heap.buffer, (short)(off+65));
        // copy first 4 bytes of the hash
        Util.arrayCopyNonAtomic(heap.buffer, (short)(off+65), out, (short)(outOff+HDKEY_FINGERPRINT_OFFSET), (short)4);
        heap.free(len);
        return HDKEY_LEN;
    }
    // TODO: refactor xprvChild and xpubChild to the same function
    //       - use arr[33] to detect if it's xpub or xprv
    // pass xprv without prefix i.e. <chaincode>0x00<prv>
    static public void xprvChild(byte[] xprv, short xprvOff,
                                 byte[] idx,  short idxOff,
                                 byte[] out,  short outOff){
        // 64 hmac, 32 random tweak
        short len = (short)96;
        short off = heap.allocate(len);
        byte[] buf = heap.buffer;

        Crypto.hmacSha512.init(xprv, xprvOff, (short)32);
        if((idx[idxOff]&0xFF)>=0x80){
            Crypto.hmacSha512.update(xprv, (short)(xprvOff+32), (short)33);            
        }else{
            Secp256k1.tempPrivateKey.setS(xprv, (short)(xprvOff+33), (short)32);
            Secp256k1.pointMultiply(Secp256k1.tempPrivateKey, Secp256k1.SECP256K1_G, (short)0, (short)65, buf, off);
            buf[off] = (byte)(0x02+(buf[(short)(off+64)] & 1));
            Crypto.hmacSha512.update(buf, off, (short)33);
        }
        // add index
        Crypto.hmacSha512.doFinal(idx, idxOff, (short)4, buf, off);
        // TODO: check if result is less than N
        // tweaking by random number helps against DPA
        // generate random number
        FiniteField.getRandomElement(Secp256k1.SECP256K1_R, (short)0,
                                     buf, (short)(off+64));
        // add it to tweak
        FiniteField.addMod(buf, (short)(off+64), 
               buf, off,
               buf, off,
               Secp256k1.SECP256K1_R, (short)0);
        // tweak private key modulo N
        FiniteField.addMod(xprv, (short)(xprvOff+33), 
               buf, off,
               buf, off,
               Secp256k1.SECP256K1_R, (short)0);
        // negate random number
        FiniteField.subtract(Secp256k1.SECP256K1_R, (short)0,
                             buf, (short)(off+64),
                             buf, (short)(off+64),
                             (short)1);
        // add negative of the random
        FiniteField.addMod(buf, (short)(off+64), 
               buf, off,
               out, (short)(outOff+33),
               Secp256k1.SECP256K1_R, (short)0);
        // copy chaincode
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        // set xprv flag
        out[(short)(outOff+32)] = (byte)0;
        heap.free(len);
    }
    // pass xpub without prefix i.e. <chaincode><pubkey>
    static public void xpubChild(byte[] xpub, short xpubOff,
                                 byte[] idx,  short idxOff,
                                 byte[] out,  short outOff){
        short len = (short)130;
        short off = heap.allocate(len);
        short fullpubOff = (short)(off+65);
        byte[] buf = heap.buffer;

        Secp256k1.uncompress(xpub, (short)(xpubOff+32), buf, fullpubOff);
        Crypto.hmacSha512.init(xpub, xpubOff, (short)32);
        // can't do hardened with xpubs
        if((idx[idxOff]&0xFF)>=0x80){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }else{
            Crypto.hmacSha512.update(xpub, (short)(xpubOff+32), (short)33);
        }
        // add index
        Crypto.hmacSha512.doFinal(idx, idxOff, (short)4, buf, off);
        // TODO: check if result is less than N
        // tweak public key
        Secp256k1.tempPrivateKey.setS(buf, off, (short)32);
        // copy chaincode
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        // tweak pubkey
        Secp256k1.tweakAdd(Secp256k1.tempPrivateKey, 
                           buf, fullpubOff, (short)65,
                           buf, off);
        Secp256k1.compress(buf, off, out, (short)(outOff+32));
        heap.free(len);
    }
}