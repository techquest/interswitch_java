package com.interswitch.techquest.interswitch.secure.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class SecureData10 {
	public String getPINBlock(String pin, String cvv2, String expiryDate, byte[] pinKey) {
        pin = null == pin || pin.equals("") ? "0000" : pin;
        cvv2 = null == cvv2 || cvv2.equals("") ? "000" : cvv2;
        expiryDate = null == expiryDate || expiryDate.equals("") ? "0000" : expiryDate;

        String pinBlockString = pin + cvv2 + expiryDate;
        int pinBlockStringLen = pinBlockString.length();
        String pinBlickLenLenString = String.valueOf(pinBlockStringLen);
        int pinBlickLenLen = pinBlickLenLenString.length();
        String clearPINBlock = String.valueOf(pinBlickLenLen) + pinBlockStringLen + pinBlockString;

        
        byte randomBytes = 0x0;
        int randomDigit = (int) ((randomBytes * 10) / 128);
        randomDigit = Math.abs(randomDigit);
        int pinpadlen = 16 - clearPINBlock.length();
        for (int i = 0; i < pinpadlen; i++) {
            clearPINBlock = clearPINBlock + randomDigit;
        }

        DESedeEngine engine = new DESedeEngine();
        DESedeParameters keyParameters = new DESedeParameters(pinKey);
        engine.init(true, keyParameters);
        byte[] clearPINBlockBytes = Hex.decode(clearPINBlock);
        byte[] encryptedPINBlockBytes = new byte[8];
        engine.processBlock(clearPINBlockBytes, 0, encryptedPINBlockBytes, 0);
        byte[] encodedEncryptedPINBlockBytes = Hex.encode(encryptedPINBlockBytes);
        String pinBlock = new String(encodedEncryptedPINBlockBytes);

        pin = "0000000000000000";
        clearPINBlock = "0000000000000000";

        zeroise(clearPINBlockBytes);
        zeroise(encryptedPINBlockBytes);
        zeroise(encodedEncryptedPINBlockBytes);

        return pinBlock;
    }

	public String getSecure(String publicKeyModulus, String publicKeyExponent, byte[] pinKey, String pan) {
        byte[] secureBytes = new byte[64];
        byte[] headerBytes = new byte[1];
        byte[] formatVersionBytes = new byte[1];
        byte[] macVersionBytes = new byte[1];
        byte[] pinDesKey = new byte[16];
        byte[] macDesKey = new byte[16];
        byte[] macBytes = new byte[4];
        byte[] customerIdBytes = new byte[10];
        byte[] footerBytes = new byte[1];
        byte[] otherBytes = new byte[14];

        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        headerBytes = HexConverter("4D");
        formatVersionBytes = HexConverter("10");
        macVersionBytes = HexConverter("10");

        pinDesKey = pinKey;

        if (pan != null) {
            int panDiff = 20 - pan.length();
            String panString = panDiff + pan;
            int panlen = 20 - panString.length();
            for (int i = 0; i < panlen; i++) {
                panString += "F";
            }
            System.out.println("panStirng " + panString);
            customerIdBytes = HexConverter(padRight(panString, 20));

        }
        


        footerBytes = HexConverter("5A");

        System.arraycopy(headerBytes, 0, secureBytes, 0, 1);
        System.out.println(headerBytes.length);
        System.arraycopy(formatVersionBytes, 0, secureBytes, 1, 1);
        System.out.println(formatVersionBytes.length);
        System.arraycopy(macVersionBytes, 0, secureBytes, 2, 1);
        System.out.println(macVersionBytes.length);
        System.arraycopy(pinDesKey, 0, secureBytes, 3, 16);
        System.out.println(pinDesKey.length);
        System.arraycopy(macDesKey, 0, secureBytes, 19, 16);
        System.out.println(new String(Hex.encode(macDesKey)) + "  "+macDesKey.length);
        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.out.println(customerIdBytes.length);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.out.println(macBytes.length);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.out.println(new String(Hex.encode(otherBytes)) + "  "+otherBytes.length);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);
        System.out.println(footerBytes.length);

        RSAEngine engine = new RSAEngine();
        RSAKeyParameters publicKeyParameters = getPublicKey(publicKeyModulus, publicKeyExponent);
        engine.init(true, publicKeyParameters);
        System.out.println(new String(Hex.encode(secureBytes)));
        byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0, secureBytes.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        String encrytedSecure = new String(encodedEncryptedSecureBytes);

        zeroise(secureBytes);

        return encrytedSecure;
    }
	
	public static void zeroise(byte[] data) {
		int len = data.length;
		
		for (int i = 0; i < len; i++)
			data[i] = 0;
	}
	

    private String padRight(String data, int maxLen)
    {

    	if(data == null || data.length() >= maxLen)
    		return data;
    	
    	int len = data.length();
    	int deficitLen = maxLen - len;
    	for(int i=0; i<deficitLen; i++)
    		data += "0";
    	
    	return data;
    }

	public byte[] generateKey()
    {
        SecureRandom sr = new SecureRandom();
        KeyGenerationParameters kgp = new KeyGenerationParameters(sr, DESedeParameters.DES_KEY_LENGTH * 16);
        DESedeKeyGenerator kg = new DESedeKeyGenerator();
        kg.init(kgp);
        
        
        byte[] desKeyBytes = kg.generateKey();
        DESedeParameters.setOddParity(desKeyBytes);
        
        return desKeyBytes;
    }
	private byte[] HexConverter(String str)
     {
        try {
            str = new String(str.getBytes(),StandardCharsets.UTF_8);
            byte[] myBytes = Hex.decode(str);
            return myBytes;
        } catch (Exception ex) {
            Logger.getLogger(SecureData10.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
     }
	 
	 public static String fromBinary2Hex(byte[] binary_data) {
			byte lo, hi;
			 byte[] hex_table = {
		        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
			// get the length of the array
			int len = binary_data.length;
			byte[] str  = new byte[len * 2];

			int index = 0;
			int creepy;
			for (int i = 0; i < len; i++) {
				creepy = (int) (binary_data[i]);
				lo = (byte) (creepy & 0x0F);
				hi = (byte) ((creepy >> 4) & 0x0F);

				str[index++] = hex_table[hi];
				str[index++] = hex_table[lo];
			}

			return new String(str);
		}
	 
	 private RSAKeyParameters getPublicKey(String modulus, String exponent)
     {
         BigInteger modulusByte = new BigInteger(Hex.decode(modulus));
         BigInteger exponentByte = new BigInteger(Hex.decode(exponent));
         RSAKeyParameters pkParameters = new RSAKeyParameters(false, modulusByte, exponentByte);
         return pkParameters;
     }
	 
}
