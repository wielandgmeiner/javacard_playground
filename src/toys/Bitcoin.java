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
    // pass xprv without prefix i.e. <chaincode>0x00<prv>
    static public void xprvChild(TransientStack st,
                           byte[] xprv, short xprvOff,
                           byte[] idx,  short idxOff,
                           byte[] out,  short outOff){
        short off = st.allocate((short)65);
        if(off < 0){
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        byte[] buf = st.buffer;

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
        // tweak private key modulo N
        FiniteField.addMod(st, xprv, (short)(xprvOff+33), 
               buf, off, 
               out, (short)(outOff+33),
               Secp256k1.SECP256K1_R, (short)0);
        // copy chaincode
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        // set xprv flag
        out[(short)(outOff+32)] = (byte)0;
        st.free((short)65);
    }
    // pass xpub without prefix i.e. <chaincode><pubkey>
    static public void xpubChild(TransientStack st,
                           byte[] xpub, short xpubOff,
                           byte[] idx,  short idxOff,
                           byte[] fullpub, short fullpubOff, // for now
                           byte[] out,  short outOff){
        short off = st.allocate((short)65);
        if(off < 0){
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        byte[] buf = st.buffer;

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
        Secp256k1.tweakAdd(Secp256k1.tempPrivateKey, 
                           fullpub, fullpubOff, (short)65,
                           out, (short)(outOff+32));
        // copy chaincode
        Util.arrayCopyNonAtomic(buf, (short)(off+32), out, outOff, (short)32);
        st.free((short)65);
    }
}