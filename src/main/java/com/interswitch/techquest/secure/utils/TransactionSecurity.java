/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.interswitch.techquest.secure.utils;

import java.security.PublicKey;
import java.util.HashMap;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Abiola.Adebanjo
 */
public class TransactionSecurity {

    private static final String SECURE = "SECURE";
    private static final String PINBLOCK = "PINBLOCK";

    public static String generateAuthData(String version, String pan, String pin, String expiryDate, String cvv2, String certFilePath) throws Exception {

        String authDataCipher = version + "Z" + pan + "Z" + pin + "Z" + expiryDate + "Z" + cvv2;
        PublicKey publicKey = Util.getPublicKey(certFilePath);
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] authDataBytes = encryptCipher.doFinal(authDataCipher.getBytes("UTF8"));
        String authData = new String(org.bouncycastle.util.encoders.Base64.encode(authDataBytes)).trim();

        return authData;
    }

    public static String getPINBlock(String pin, String cvv2, String expiryDate, byte[] keyBytes) {
        pin = null == pin || pin.equals("") ? "0000" : pin;
        cvv2 = null == cvv2 || cvv2.equals("") ? "000" : cvv2;
        expiryDate = null == expiryDate || expiryDate.equals("") ? "0000"
                : expiryDate;

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
        DESedeParameters keyParameters = new DESedeParameters(keyBytes);
        engine.init(true, keyParameters);
        byte[] clearPINBlockBytes = Hex.decode(clearPINBlock);
        byte[] encryptedPINBlockBytes = new byte[8];
        engine.processBlock(clearPINBlockBytes, 0, encryptedPINBlockBytes, 0);
        byte[] encodedEncryptedPINBlockBytes = Hex.encode(encryptedPINBlockBytes);
        String pinBlock = new String(encodedEncryptedPINBlockBytes);

        pin = "0000000000000000";
        clearPINBlock = "0000000000000000";

        Util.zeroise(clearPINBlockBytes);
        Util.zeroise(encryptedPINBlockBytes);
        Util.zeroise(encodedEncryptedPINBlockBytes);

        return pinBlock;
    }

    public static HashMap<String, String> generateSecureData(String pan, String cvv, String expiryDate, String susbscriberID, String transCode, String amt, String phoneNum, String custNum, String paymentItemCode, String cardName, String certFilePath) throws Exception {

        HashMap<String, String> secureData = new HashMap<String, String>();

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
        byte[] keyBytes = Util.generateKey();

        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        headerBytes = Util.HexConverter("4D");
        formatVersionBytes = Util.HexConverter("10");
        macVersionBytes = Util.HexConverter("10");

        pinDesKey = keyBytes;

        if (pan != null || pan != "") {
            int panDiff = 20 - pan.length();
            String panString = panDiff + pan;
            int panlen = 20 - panString.length();
            for (int i = 0; i < panlen; i++) {
                panString += "F";
            }

            customerIdBytes = Util.HexConverter(Util.padRight(panString, 20));

        }

        String macData = Util.getMACDataVersion9(susbscriberID, cardName, transCode, amt, phoneNum, custNum, paymentItemCode);
        macBytes = Hex.decode(Util.getMAC(macData, macDesKey, 11));
        footerBytes = Util.HexConverter("5A");

        System.arraycopy(headerBytes, 0, secureBytes, 0, 1);
        System.arraycopy(formatVersionBytes, 0, secureBytes, 1, 1);
        System.arraycopy(macVersionBytes, 0, secureBytes, 2, 1);
        System.arraycopy(pinDesKey, 0, secureBytes, 3, 16);
        System.arraycopy(macDesKey, 0, secureBytes, 19, 16);
        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        RSAEngine engine = new RSAEngine();
        RSAKeyParameters publicKeyParameters = Util.getRSAKeyParameters(certFilePath);
        engine.init(true, publicKeyParameters);
        byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0, secureBytes.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        String encrytedSecure = new String(encodedEncryptedSecureBytes);

        Util.zeroise(secureBytes);

        String pinBlock = getPINBlock(pan, cvv, expiryDate, keyBytes);

        secureData.put(SECURE, encrytedSecure);
        secureData.put(PINBLOCK, pinBlock);

        return secureData;
    }
}
