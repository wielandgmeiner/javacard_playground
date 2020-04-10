/* Do what the fuck you want license. */
package toys;

// import using java card API interface.
import javacard.framework.*;
import javacard.security.*;

/* 
 * Package: toys
 * Filename: CalculatorApplet.java 
 * Class: CalculatorApplet
 */
public class CalculatorApplet extends Applet{

    // Define the value of CLA/INS in APDU, you can also define P1, P2.
    private static final byte CLA_CALC                 = (byte)0xB0;

    private static final byte PBKDF2_HMAC_SHA512       = (byte)0xA0;
    private static final byte INS_SHA256               = (byte)0xA1;
    private static final byte INS_HMAC_SHA256          = (byte)0xA2;
    private static final byte INS_SHA512               = (byte)0xA3;
    private static final byte INS_HMAC_SHA512          = (byte)0xA4;
    // finite field math
    private static final byte INS_ADDMOD_FP            = (byte)0xA5;
    private static final byte INS_ADDMOD_N             = (byte)0xA6;
    // ecc
    private static final byte INS_ECC_TWEAK_ADD        = (byte)0xA7;
    private static final byte INS_ECC_ADD              = (byte)0xA8;
    // bip32
    private static final byte INS_XPRV_CHILD           = (byte)0xA9;
    private static final byte INS_XPUB_CHILD           = (byte)0xAA;

    private byte[] scratch;
    private ECPrivateKey bip32tempKey;
    private byte[] ikey;
    private byte[] okey;


    // Create an instance of the Applet subclass using its constructor, 
    // and to register the instance.
    public static void install(byte[] bArray, short bOffset, byte bLength){
        // Only one applet instance can be successfully registered each time 
        // the JCRE calls the Applet.install method.
        new CalculatorApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public CalculatorApplet(){
        Secp256k1.init();
        Crypto.init();
        scratch = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
        bip32tempKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(bip32tempKey);
        // for pbkdf2
        ikey = JCSystem.makeTransientByteArray(HMACDigest.ALG_SHA_512_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        okey = JCSystem.makeTransientByteArray(HMACDigest.ALG_SHA_512_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }
    // Process the command APDU, 
    // All APDUs are received by the JCRE and preprocessed. 
    public void process(APDU apdu){
        // Select the Applet, through the select method, this applet is selectable, 
        // After successful selection, all APDUs are delivered to the currently selected applet
        // via the process method.
        if (selectingApplet()){
            return;
        }
        // Get the APDU buffer byte array.
        byte[] buf = apdu.getBuffer();
        // Calling this method indicates that this APDU has incoming data. 
        apdu.setIncomingAndReceive();
        
        // If the CLA is not equal to 0xB0(CLA_TEAPOT),  throw an exception.
        if(buf[ISO7816.OFFSET_CLA] != CLA_CALC){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // check we have at least one element
        // and list is formed correctly
        short len = Util.makeShort((byte)0, buf[ISO7816.OFFSET_LC]);
        byte numElements = checkList(buf, (short)ISO7816.OFFSET_CDATA, len);
        // if(numElements < 1){
        //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // }
        // Dispatch INS in APDU.
        short offset = (short)ISO7816.OFFSET_CDATA;

        switch (buf[ISO7816.OFFSET_INS]){
        case INS_SHA256:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.sha256.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_SHA512:
            if(numElements != 1){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.sha512.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        case INS_HMAC_SHA256:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.hmacSha256.init(buf, (short)(offset+1), buf[offset]);
            offset += (short)(buf[offset]+1);
            Crypto.hmacSha256.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_HMAC_SHA512:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Crypto.hmacSha512.init(buf, (short)(offset+1), buf[offset]);
            offset += (short)(buf[offset]+1);
            Crypto.hmacSha512.doFinal(buf, (short)(offset+1), buf[offset], buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        case INS_ADDMOD_FP:
            // TODO: check that arguments are 32 byte long
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            addMod(buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_FP, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_ADDMOD_N:
            // TODO: check that arguments are 32 byte long
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            addMod(buf, (short)(offset+1), buf, (short)(offset+34), buf, (short)0, Secp256k1.SECP256K1_R, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)32);
            break;
        case INS_ECC_TWEAK_ADD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            bip32tempKey.setS(buf, (short)(offset+1), (short)32);
            Secp256k1.tweakAdd(bip32tempKey, 
                               buf, (short)(offset+34), (short)65, 
                               buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        case INS_ECC_ADD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayFillNonAtomic(scratch, (short)0, (short)32, (byte)0);
            scratch[31] = (byte)1;
            bip32tempKey.setS(scratch, (short)0, (short)32);
            bip32tempKey.setG(buf, (short)(offset+1), (short)65);
            Secp256k1.tweakAdd(bip32tempKey, 
                               buf, (short)(offset+67), (short)65, 
                               buf, (short)0);
            bip32tempKey.setG(Secp256k1.SECP256K1_G, (short)0, (short)65);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        // <xprv><index>
        case INS_XPRV_CHILD:
            if(numElements != 2){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // TODO: check args len
            xprvChild(buf, (short)(offset+1), buf, (short)(offset+67), buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        // <xpub><index><uncompressed pubkey>
        case INS_XPUB_CHILD:
            if(numElements != 3){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // TODO: check args len
            xpubChild(buf, (short)(offset+1), 
                      buf, (short)(offset+67), 
                      buf, (short)(offset+67+5), 
                      buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)65);
            break;
        case PBKDF2_HMAC_SHA512:
            if(numElements != 3){
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short iterations = Util.getShort(buf, (short)(offset+1));
            pbkdf2(buf, (short)(offset+4), buf[(short)(offset+3)], 
                   buf, (short)(offset+5+buf[(short)(offset+3)]), buf[(short)(offset+4+buf[(short)(offset+3)])], 
                   iterations,
                   buf, (short)0);
            apdu.setOutgoingAndSend((short)0, (short)64);
            break;
        default:
            // If you don't know the INS, throw an exception.
            buf[0] = numElements;
            apdu.setOutgoingAndSend((short)0, (short)1);
            // ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    private void pbkdf2(byte[] pass, short pOff, short pLen,
                        byte[] salt, short sOff, short sLen,
                        short iterations,
                        byte[] out, short outOff){
        if(pLen > HMACDigest.ALG_SHA_512_BLOCK_SIZE) {
            Crypto.sha512.reset();
            Crypto.sha512.doFinal(pass, pOff, pLen, ikey, (short)0);
        }else{
            Util.arrayFillNonAtomic(ikey, (short)0, HMACDigest.ALG_SHA_512_BLOCK_SIZE, (byte)0);
            Util.arrayCopyNonAtomic(pass, pOff, ikey, (short)0, pLen);
        }
        Util.arrayCopyNonAtomic(ikey, (short)0, okey, (short)0, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
        for(short i = (short)0; i < HMACDigest.ALG_SHA_512_BLOCK_SIZE; i++) {
            ikey[i] = (byte)(ikey[i]^HMACDigest.IPAD);
            okey[i] = (byte)(okey[i]^HMACDigest.OPAD);
        }
        // i = 1
        Util.arrayFillNonAtomic(scratch, (short)0, (short)4, (byte)0);
        scratch[3] = (byte)1;
        Crypto.sha512.reset();
        // U
        Crypto.sha512.update(ikey, (short)0, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
        Crypto.sha512.update(salt, sOff, sLen);
        Crypto.sha512.doFinal(scratch, (short)0, (short)4, scratch, (short)0);
        Crypto.sha512.update(okey, (short)0, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
        Crypto.sha512.doFinal(scratch, (short)0, (short)64, scratch, (short)0);

        Util.arrayCopyNonAtomic(scratch, (short)0, out, outOff, (short)64);
        for(short j=(short)2; j<=iterations; j++){
            Crypto.sha512.update(ikey, (short)0, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
            Crypto.sha512.doFinal(scratch, (short)0, (short)64, scratch, (short)0);
            Crypto.sha512.update(okey, (short)0, HMACDigest.ALG_SHA_512_BLOCK_SIZE);
            Crypto.sha512.doFinal(scratch, (short)0, (short)64, scratch, (short)0);
            for(short i = (short)0; i < 64; i++) {
                out[(short)(outOff+i)] = (byte)(out[(short)(outOff+i)]^scratch[i]);
            }
        }
    }
    // pass xprv without prefix i.e. <chaincode>0x00<prv>
    // WARNING: uses scratch[:65]
    private void xprvChild(byte[] xprv, short xprvOff,
                           byte[] idx,  short idxOff,
                           byte[] out,  short outOff){

        Crypto.hmacSha512.init(xprv, xprvOff, (short)32);
        if((idx[idxOff]&0xFF)>=0x80){
            Crypto.hmacSha512.update(xprv, (short)(xprvOff+32), (short)33);            
        }else{
            bip32tempKey.setS(xprv, (short)(xprvOff+33), (short)32);
            Secp256k1.pointMultiply(bip32tempKey, Secp256k1.SECP256K1_G, (short)0, (short)65, scratch, (short)0);
            scratch[(short)0] = (byte)(0x02+(scratch[(short)64] & 1));
            Crypto.hmacSha512.update(scratch, (short)0, (short)33);
        }
        // add index
        Crypto.hmacSha512.doFinal(idx, idxOff, (short)4, scratch, (short)0);
        // TODO: check if result is less than N
        // tweak private key modulo N
        addMod(xprv, (short)(xprvOff+33), 
               scratch, (short)0, 
               out, (short)(outOff+33),
               Secp256k1.SECP256K1_R, (short)0);
        // copy chaincode
        Util.arrayCopyNonAtomic(scratch, (short)32, out, outOff, (short)32);
        // set xprv flag
        out[(short)(outOff+32)] = (byte)0;
    }
    // pass xpub without prefix i.e. <chaincode><pubkey>
    // WARNING: uses scratch[:65]
    private void xpubChild(byte[] xpub, short xpubOff,
                           byte[] idx,  short idxOff,
                           byte[] fullpub, short fullpubOff, // for now
                           byte[] out,  short outOff){

        Crypto.hmacSha512.init(xpub, xpubOff, (short)32);
        // can't do hardened with xpubs
        if((idx[idxOff]&0xFF)>=0x80){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }else{
            Crypto.hmacSha512.update(xpub, (short)(xpubOff+32), (short)33);
        }
        // add index
        Crypto.hmacSha512.doFinal(idx, idxOff, (short)4, scratch, (short)0);
        // TODO: check if result is less than N
        // tweak public key
        bip32tempKey.setS(scratch, (short)0, (short)32);
        Secp256k1.tweakAdd(bip32tempKey, 
                           fullpub, fullpubOff, (short)65,
                           out, (short)(outOff+32));
        // copy chaincode
        Util.arrayCopyNonAtomic(scratch, (short)32, out, outOff, (short)32);
    }
    // constant time modulo addition
    // can tweak in place
    // WARNING: uses scratch[:32]
    private void addMod(byte[] a,     short aOff, 
                        byte[] b,     short bOff, 
                        byte[] out,   short outOff, 
                        byte[] mod,   short modOff){
        // addition with carry
        short carry = add(a, aOff, b, bOff, scratch, (short)0);
        // subtract in any case and store result in output buffer
        short scarry = subtract(scratch, (short)0, mod, modOff, out, outOff);
        // check if we actually needed to subtract
        // TODO: remove branching and use scratch index instead
        //       this would require refactoring bip32xprv as well
        if(carry!=0 || scarry==0){
            // we are fine, but we need to copy something, 
            // so let's copy output buffer to temp buffer
            Util.arrayCopyNonAtomic(out, outOff, scratch, (short)0, (short)32);
        }else{
            // there was no overflow - copy from temp buffer to output
            Util.arrayCopyNonAtomic(scratch, (short)0, out, outOff, (short)32);
        }
    }
    // addition of two 256-bit numbers, returns carry
    // WARNING: can't do subtraction in place with different offsets
    // output buffer should be a different one, 
    // use temp buffer, scratch for example
    private short add(byte[] a, short aOff,
                      byte[] b, short bOff,
                      byte[] out, short outOff){
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((short)(a[(short)(aOff+i)]&0xFF)+(short)(b[(short)(bOff+i)]&0xFF)+carry);
            scratch[i] = (byte)carry;
            carry = (short)(carry>>8);
        }
        return carry;
    }
    // subtraction of two 256-bit numbers, returns carry
    // WARNING: can't do subtraction in place with different offsets
    // output buffer should be a different one, 
    // use temp buffer, scratch for example
    // TODO: get rid of branching in carry assignment
    private short subtract(byte[] a, short aOff, 
                     byte[] b, short bOff,
                     byte[] out, short outOff){
        short carry = 0;
        for(short i=31; i>=0; i--){
            carry = (short)((a[(short)(aOff+i)]&0xFF)-(b[(short)(bOff+i)]&0xFF)-carry);
            out[(short)(outOff+i)] = (byte)carry;
            carry = (short)(((carry>>8)!=0) ? 1 : 0);
        }
        return carry;
    }
    // constant time comparison
    private boolean isGreater(byte[] a, short aOff,
                              byte[] b, short bOff){
        // if a more than b, b-a will be negative - we will get non-zero carry
        return (subtract(b, bOff, a, aOff, scratch, (short)0)!=0);
    }
    // checks that buffer contains a list of elements
    // encoded as <len><data><len><data>...
    // and returns number of elements
    // -1 if encoding is not correct
    private byte checkList(byte[] buf, short offset, short len){
        short end = (short)(offset+len);
        byte numElements = (byte)0;
        while(offset < end){
            offset += buf[offset];
            offset++;
            numElements++;
        }
        if(offset > end){
            return -1;
        }
        return numElements;
    }
}
