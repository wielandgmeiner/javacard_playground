package toys;

import javacard.framework.*;
import javacard.security.*;

/**
 * Utility methods to work with the SECP256k1 curve. This class is not meant to be instantiated, but its init method
 * must be called during applet installation.
 */
public class Secp256k1 {
    static final byte[] SECP256K1_FP = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };
    static final byte[] SECP256K1_A = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
    };
    static final byte[] SECP256K1_B = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
    };
    static final byte[] SECP256K1_G = {
        (byte)0x04,
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };
    static final byte[] SECP256K1_R = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };
    // to calculate square root
    static final byte[] SECP256K1_ROOT = {
        (byte)0x3F,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xBF,(byte)0xFF,(byte)0xFF,(byte)0x0C
    };

    static final byte SECP256K1_K = (byte)0x01;

    static final short SECP256K1_KEY_SIZE = 256;

    // constants from JavaCard 3.0.5
    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6;
    private static final byte ALG_EC_PACE_GM          = 5;

    static private KeyAgreement ecMult;
    static private KeyAgreement ecMultX;
    static private KeyAgreement ecAdd;
    static private Signature sig;
    static public ECPrivateKey tempPrivateKey;

    /**
     * Allocates objects needed by this class. Must be invoked during the applet installation exactly 1 time.
     */
    static void init() {
        ecMult = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        ecMultX = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        ecAdd = KeyAgreement.getInstance(ALG_EC_PACE_GM, false);
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        tempPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(tempPrivateKey);
    }

    /**
     * Sets the SECP256k1 curve parameters to the given ECKey (public or private).
     *
     * @param key the key where the curve parameters must be set
     */
    static void setCommonCurveParameters(ECKey key) {
        key.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
        key.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
        key.setFieldFP(SECP256K1_FP, (short)0, (short)SECP256K1_FP.length);
        key.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
        key.setR(SECP256K1_R, (short)0, (short)SECP256K1_R.length);
        key.setK(SECP256K1_K);
    }

    static KeyPair newKeyPair() {
        KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, SECP256K1_KEY_SIZE);
        setCommonCurveParameters((ECPrivateKey)kp.getPrivate());
        setCommonCurveParameters((ECPublicKey)kp.getPublic());
        return kp;
    }
    // TODO: doesn't check if point is on the curve
    static void uncompress(TransientStack st,
                           byte[] point, short pOff,
                           byte[] out, short outOff){
        // allocate space for y coordinate and number 7...
        short len = (short)64;
        short off = st.allocate(len);
        byte[] buf = st.buffer;
        if(off < 0){ // failed to allocate memory
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        // calculate x^3
        FiniteField.powShortModFP(st, point, (short)(pOff+1), (short)3, buf, off);
        buf[(short)(off+63)]=0x07;
        // add 7
        FiniteField.addMod(st, buf, off, buf, (short)(off+32), buf, off, SECP256K1_FP, (short)0);
        // square root
        FiniteField.powModFP(st, buf, off, SECP256K1_ROOT, (short)0, buf, (short)(off+32));
        // check sign and negate if necessary
        if((point[pOff]-0x02) != (buf[(short)(off+63)]&0x01)){
            FiniteField.subtract(SECP256K1_FP, (short)0, buf, (short)(off+32), buf, (short)(off+32), (short)1);
        }
        Util.arrayCopyNonAtomic(point, (short)(pOff+1), buf, off, (short)32);
        out[outOff] = (byte)0x04;
        Util.arrayCopyNonAtomic(buf, off, out, (short)(outOff+1), (short)64);
        st.free(len);
    }
    static void compress(TransientStack st, 
                         byte[] point, short pOff,
                         byte[] out, short outOff){
        short len = (short)32;
        short off = st.allocate(len);
        byte[] buf = st.buffer;
        if(off < 0){ // failed to allocate memory
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        byte sign = (byte)(0x02+(point[(short)(pOff+64)]&0x01));
        // because maybe it's the same buffer...
        Util.arrayCopyNonAtomic(point, (short)(pOff+1), buf, (short)0, (short)32);
        out[outOff] = sign;
        Util.arrayCopyNonAtomic(buf, (short)0, out, (short)(outOff+1), (short)32);
        st.free(len);
    }
    /**
     * Multiplies a scalar in the form of a private key by the given point. Internally uses a special version of EC-DH
     * supported since JavaCard 3.0.5 which outputs both X and Y in their uncompressed form.
     *
     * @param privateKey the scalar in a private key object
     * @param point the point to multiply
     * @param pointOffset the offset of the point
     * @param pointLen the length of the point
     * @param out the output buffer
     * @param outOffset the offset in the output buffer
     * @return the length of the data written in the out buffer
     */
    static short pointMultiply(
                    ECPrivateKey privateKey, 
                    byte[] point, short pointOffset, short pointLen, 
                    byte[] out, short outOffset)
    {
        ecMult.init(privateKey);
        return ecMult.generateSecret(point, pointOffset, pointLen, out, outOffset);
    }
    /**
     * Adds tweak*G to the point. Returs P+tweak*G.
     * If you want to add two points: P1 + P2
     * set tweak=1, tweak.G = P1, point = P2 -> you'll get it.
     */
    static short tweakAdd(
                    ECPrivateKey tweak,
                    byte[] point, short pOff, short pLen,
                    byte[] out, short outOff
                ){
        ecAdd.init(tweak);
        return ecAdd.generateSecret(point, pOff, pLen, out, outOff);
    }
    /**
     * Preforms ECDH key agreement. 
     * Writes x-coordinate of the point multiplication result to the output buffer.
     *
     * @param privateKey the scalar in a private key object
     * @param point the point to multiply
     * @param pointOffset the offset of the point
     * @param pointLen the length of the point
     * @param out the output buffer
     * @param outOffset the offset in the output buffer
     * @return the length of the data written in the out buffer
     */
    static short ecdh(
                    ECPrivateKey privateKey, 
                    byte[] point, short pointOffset, short pointLen, 
                    byte[] out, short outOffset)
    {
        ecMultX.init(privateKey);
        return ecMultX.generateSecret(point, pointOffset, pointLen, out, outOffset);
    }

    static short sign(
                    ECPrivateKey privateKey, 
                    byte[] msg, short msgOffset,
                    byte[] out, short outOffset)
    {
        sig.init(privateKey, Signature.MODE_SIGN);
        return sig.signPreComputedHash(msg, msgOffset, (short)32, out, outOffset);
    }
}
