// define package name.
package sextoys;

// import using java card API interface.
import javacard.framework.*;

/* 
 * Package: sextoys
 * Filename: Teapot.java 
 * Class: Teapot
 */
public class Teapot extends Applet{

   // Define the value of CLA/INS in APDU, you can also define P1, P2.
   private static final byte CLA_TEAPOT               = (byte)0xB0;
   private static final byte INS_GET                  = (byte)0xA1;
   private static final byte INS_PUT                  = (byte)0xA2;

   private static final byte MAX_SIZE                 = (byte)64;

   // Default secret
   private byte[] secret = {
      'I',' ','a','m',' ','a',' ','t',
      'e','a','p','o','t',' ','g','i',
      'm','m','e',' ','s','o','m','e',
      ' ','t','e','a',' ','p','l','z',
      // Dummy data. Do I need it?
      'I',' ','a','m',' ','a',' ','t',
      'e','a','p','o','t',' ','g','i',
      'm','m','e',' ','s','o','m','e',
      ' ','t','e','a',' ','p','l','z'
   };
   private byte secretlen = (byte)32;

   // Create an instance of the Applet subclass using its constructor, 
   // and to register the instance.
   public static void install(byte[] bArray, short bOffset, byte bLength){
      // Only one applet instance can be successfully registered each time 
      // the JCRE calls the Applet.install method.
      new Teapot().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
   }
   // Process the command APDU, 
   // All APDUs are received by the JCRE and preprocessed. 
   public void process(APDU apdu){
      // Select the Applet, through the select method, this applet is selectable, 
      // After successful selection, all APDUs are delivered to the currently selected applet
      // via the process method.
      if (selectingApplet())
      {
         return;
      }
      // Get the APDU buffer byte array.
      byte[] buf = apdu.getBuffer();
      // Calling this method indicates that this APDU has incoming data. 
      apdu.setIncomingAndReceive();
      
      // If the CLA is not equal to 0xB0(CLA_TEAPOT),  throw an exception.
      if(buf[ISO7816.OFFSET_CLA] != CLA_TEAPOT){
         ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      }
      // Dispatch INS in APDU.
      switch (buf[ISO7816.OFFSET_INS]){
         // The APDU format can be "B0 A1 P1 P2 Lc Data Le", 
         // such as "B0A10000" or "B0A101020311223300".
      case INS_GET:
         SendData(apdu);
         break;
         // The APDU format can be "B0 A2 P1 P2 Lc Data Le",
         // such as "B0A2000002112200".
         // Up to 32 bytes
      case INS_PUT:
         if(buf[ISO7816.OFFSET_LC] > MAX_SIZE){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         }
         // copy content of the buffer to the secret array
         secretlen = buf[ISO7816.OFFSET_LC];
         // should be atomic
         Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, secret, (short)0, (short)secretlen);
         SendData(apdu);
         break;
      default:
         // If you don't know the INS, throw an exception.
         ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
   }
   
   // Define a function named 'SendData'
   private void SendData(APDU apdu) 
   {
      // Get the apdu buffer datas again.
      byte [] buffer = apdu.getBuffer();

      // Copy secret to APDU Buffer.
      Util.arrayCopyNonAtomic(secret, (short)0, buffer, (short)0, secretlen);
         
      // Set the data transfer direction to outbound.
      apdu.setOutgoing();
      // Set the actual length of response data.
      apdu.setOutgoingLength(secretlen);
      // Sends the data of APDU buffer 'buffer', the length is 'len' bytes,  the offset is 0.
      apdu.sendBytes((short)0, secretlen);
   }

}
