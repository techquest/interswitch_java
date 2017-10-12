package com.interswitch.techquest.auth.helpers;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Hex;

import com.interswitch.techquest.auth.Interswitch;

/**
 *
 * @author Abiola.Adebanjo
 */
public class TransactionSecurity {
	
	
    public static String getAuthData(String publicExponent, String publicModulus, String version, String pan, String expDate, String cvv, String pin) throws Exception 
    {

        String authDataCipher = version + "Z" + pan + "Z" + pin + "Z" + expDate + "Z" + cvv;
        PublicKey publicKey = getPublicKey(publicExponent, publicModulus);
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] authDataBytes = encryptCipher.doFinal(authDataCipher.getBytes("UTF8"));
        String authData = new String(org.bouncycastle.util.encoders.Base64.encode(authDataBytes)).trim();

        return authData;
    }
    
    public static String getAuthData(String publicCertPath, String version, String pan, String expDate, String cvv, String pin) throws Exception 
    {

        String authDataCipher = version + "Z" + pan + "Z" + pin + "Z" + expDate + "Z" + cvv;
        PublicKey publicKey = getPublicKey(publicCertPath);
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] authDataBytes = encryptCipher.doFinal(authDataCipher.getBytes("UTF8"));
        String authData = new String(org.bouncycastle.util.encoders.Base64.encode(authDataBytes)).trim();

        return authData;
    }

    public HashMap<String, String> getSecureData(String publicCertPath, String pan, String expDate, String cvv, String pin, int macVer) throws Exception {

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
        byte[] keyBytes = generateKey();

        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        headerBytes = HexConverter("4D");
        formatVersionBytes = HexConverter("10");
        macVersionBytes = HexConverter("10");

        pinDesKey = keyBytes;

        if (pan != null && pan != "") {
            int panDiff = 20 - pan.length();
            String panString = panDiff + pan;
            int panlen = 20 - panString.length();
            for (int i = 0; i < panlen; i++) {
                panString += "F";
            }

            customerIdBytes = HexConverter(padRight(panString, 20));

        }

        String macData = "";
//        macBytes = Hex.decode(getMAC(macData, macDesKey, 11));
        String mac = getMAC(macData, macDesKey, macVer);
        macBytes = Hex.decode(mac);
        footerBytes = HexConverter("5A");

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
        RSAKeyParameters publicKeyParameters = getRSAKeyParameters(publicCertPath);
        engine.init(true, publicKeyParameters);
        byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0, secureBytes.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        String encrytedSecure = new String(encodedEncryptedSecureBytes);

        zeroise(secureBytes);

        String pinBlock = getPINBlock(pin, cvv, expDate, keyBytes);

        secureData.put(Interswitch.SECURE, encrytedSecure);
        secureData.put(Interswitch.PINBLOCK, pinBlock);
        secureData.put(Interswitch.MACDATA, mac);

        return secureData;
    }
    
    public HashMap<String, String> getSecureData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin, int macVer) throws Exception {

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
        byte[] keyBytes = generateKey();

        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        headerBytes = HexConverter("4D");
        formatVersionBytes = HexConverter("10");
        macVersionBytes = HexConverter("10");

        pinDesKey = keyBytes;

        if (pan != null && pan != "") {
            int panDiff = 20 - pan.length();
            String panString = panDiff + pan;
            int panlen = 20 - panString.length();
            for (int i = 0; i < panlen; i++) {
                panString += "F";
            }

            customerIdBytes = HexConverter(padRight(panString, 20));

        }

        String macData = "";
//        macBytes = Hex.decode(getMAC(macData, macDesKey, 11));
        String mac = getMAC(macData, macDesKey, macVer);
        macBytes = Hex.decode(mac);
        footerBytes = HexConverter("5A");

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
        RSAKeyParameters publicKeyParameters = getPublicRSAKey(publicModulus, publicExponent);
        engine.init(true, publicKeyParameters);
        byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0, secureBytes.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        String encrytedSecure = new String(encodedEncryptedSecureBytes);

        zeroise(secureBytes);

        String pinBlock = getPINBlock(pin, cvv, expDate, keyBytes);

        secureData.put(Interswitch.SECURE, encrytedSecure);
        secureData.put(Interswitch.PINBLOCK, pinBlock);
        secureData.put(Interswitch.MACDATA, mac);

        return secureData;
    }
    
    public HashMap<String, String> getSecureData(String publicCertPath, String pan, String expDate, String cvv, String pin, HashMap<String,String>transactionParameters, int macVer) throws Exception {

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
        byte[] keyBytes = generateKey();

        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        headerBytes = HexConverter("4D");
        formatVersionBytes = HexConverter("10");
        macVersionBytes = HexConverter("10");

        pinDesKey = keyBytes;

        if (pan != null && pan != "") {
            int panDiff = 20 - pan.length();
            String panString = panDiff + pan;
            int panlen = 20 - panString.length();
            for (int i = 0; i < panlen; i++) {
                panString += "F";
            }

            customerIdBytes = HexConverter(padRight(panString, 20));

        }

        String macData = getMACDataVersion9(transactionParameters);
        String mac = getMAC(macData, macDesKey, macVer);
        macBytes = Hex.decode(mac);
        footerBytes = HexConverter("5A");

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
        RSAKeyParameters publicKeyParameters = getRSAKeyParameters(publicCertPath);
        engine.init(true, publicKeyParameters);
        byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0, secureBytes.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        String encrytedSecure = new String(encodedEncryptedSecureBytes);

        zeroise(secureBytes);

        String pinBlock = getPINBlock(pin, cvv, expDate, keyBytes);

        secureData.put(Interswitch.SECURE, encrytedSecure);
        secureData.put(Interswitch.PINBLOCK, pinBlock);
        secureData.put(Interswitch.MACDATA, mac);

        return secureData;
    }
    
    
    public HashMap<String, String> getSecureData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin, HashMap<String,String>transactionParameters, int macVer) throws Exception {

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
        byte[] keyBytes = generateKey();

        System.arraycopy(customerIdBytes, 0, secureBytes, 35, 10);
        System.arraycopy(macBytes, 0, secureBytes, 45, 4);
        System.arraycopy(otherBytes, 0, secureBytes, 49, 14);
        System.arraycopy(footerBytes, 0, secureBytes, 63, 1);

        headerBytes = HexConverter("4D");
        formatVersionBytes = HexConverter("10");
        macVersionBytes = HexConverter("10");

        pinDesKey = keyBytes;

        if (pan != null && pan != "") {
            int panDiff = 20 - pan.length();
            String panString = panDiff + pan;
            int panlen = 20 - panString.length();
            for (int i = 0; i < panlen; i++) {
                panString += "F";
            }

            customerIdBytes = HexConverter(padRight(panString, 20));

        }

        String macData = getMACDataVersion9(transactionParameters);
//        macBytes = Hex.decode(getMAC(macData, macDesKey, 11));
        String mac = getMAC(macData, macDesKey, macVer);
        macBytes = Hex.decode(mac);
        footerBytes = HexConverter("5A");

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
        RSAKeyParameters publicKeyParameters = getPublicRSAKey(publicModulus, publicExponent);
        engine.init(true, publicKeyParameters);
        byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0, secureBytes.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        String encrytedSecure = new String(encodedEncryptedSecureBytes);

        zeroise(secureBytes);

        String pinBlock = getPINBlock(pin, cvv, expDate, keyBytes);

        secureData.put(Interswitch.SECURE, encrytedSecure);
        secureData.put(Interswitch.PINBLOCK, pinBlock);
        secureData.put(Interswitch.MACDATA, mac);

        return secureData;
    }

    private static String getPINBlock(String pin, String cvv2, String expiryDate, byte[] keyBytes) {
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
//        System.out.println(randomDigit);
        int pinpadlen = 16 - clearPINBlock.length();
//        System.out.println(pinpadlen);
        for (int i = 0; i < pinpadlen; i++) {
            clearPINBlock = clearPINBlock + randomDigit;
        }
//        System.out.println(clearPINBlock);
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

        zeroise(clearPINBlockBytes);
        zeroise(encryptedPINBlockBytes);
        zeroise(encodedEncryptedPINBlockBytes);

        return pinBlock;
    }

    private static RSAKeyParameters getRSAKeyParameters(String certFilePath) throws Exception {
        String certContent = "";
        FileReader fileReader = new FileReader(certFilePath);
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            certContent = certContent.concat(line).concat("\n");
        }
        bufferedReader.close();

        StringReader reader = new StringReader(certContent);
        PEMParser pemParser = new PEMParser(reader);
        X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) pemParser.readObject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
        RSAKeyParameters rsaKeyParameters = (RSAKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);
        pemParser.close();
        return rsaKeyParameters;
    }

    private static PublicKey getPublicKey(String certFilePath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyParameters rSAKeyParameters = getRSAKeyParameters(certFilePath);
        RSAPublicKeySpec publicKeyspec = new RSAPublicKeySpec(rSAKeyParameters.getModulus(), rSAKeyParameters.getExponent());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(publicKeyspec);

        return publicKey;
    }
    
    private static PublicKey getPublicKey(String publicExponent, String publicModulus) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        RSAPublicKeySpec publicKeyspec = new RSAPublicKeySpec(new BigInteger(publicModulus, 16), new BigInteger(publicExponent, 16));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(publicKeyspec);

        return publicKey;
    }
    
    private RSAKeyParameters getPublicRSAKey(String modulus, String exponent)
    {
        BigInteger modulusByte = new BigInteger(Hex.decode(modulus));
        BigInteger exponentByte = new BigInteger(Hex.decode(exponent));
        RSAKeyParameters pkParameters = new RSAKeyParameters(false, modulusByte, exponentByte);
        return pkParameters;
    }

    private static byte[] HexConverter(String str) {
        try {
            str = new String(str.getBytes(), StandardCharsets.UTF_8);
            byte[] myBytes = Hex.decode(str);
            return myBytes;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static String padRight(String data, int maxLen) {

        if (data == null || data.length() >= maxLen) {
            return data;
        }

        int len = data.length();
        int deficitLen = maxLen - len;
        for (int i = 0; i < deficitLen; i++) {
            data += "0";
        }

        return data;
    }

    private static void zeroise(byte[] data) {
        int len = data.length;

        for (int i = 0; i < len; i++) {
            data[i] = 0;
        }
    }

    private static String getMAC(String macData, byte[] macKey, int macVersion) {
        byte[] macBytes = new byte[4];
        byte[] macDataBytes = macData.getBytes();
        byte[] encodedMacBytes;
        String macCipher1;
        SecretKeySpec keyParameters1;
        Mac engine1;
        if (macVersion == 8) {
            macCipher1 = "";

            try {
                keyParameters1 = new SecretKeySpec(macKey, "HmacSHA1");
                engine1 = Mac.getInstance(keyParameters1.getAlgorithm());
                engine1.init(keyParameters1);
                encodedMacBytes = macData.getBytes();
                macBytes = engine1.doFinal(encodedMacBytes);
                macCipher1 = new String(Hex.encode(macBytes), "UTF-8");
            } catch (InvalidKeyException var11) {
                ;
            } catch (NoSuchAlgorithmException var12) {
                ;
            } catch (UnsupportedEncodingException var13) {
                ;
            }

            return macCipher1;
        } else if (macVersion == 12) {
            macCipher1 = "";

            try {
                keyParameters1 = new SecretKeySpec(macKey, "HmacSHA256");
                engine1 = Mac.getInstance(keyParameters1.getAlgorithm());
                engine1.init(keyParameters1);
                encodedMacBytes = macData.getBytes();
                macBytes = engine1.doFinal(encodedMacBytes);
                macCipher1 = new String(Hex.encode(macBytes), "UTF-8");
            } catch (InvalidKeyException var14) {
                ;
            } catch (NoSuchAlgorithmException var15) {
                ;
            } catch (UnsupportedEncodingException var16) {
                ;
            }

            return macCipher1;
        } else {
            CBCBlockCipherMac macCipher = new CBCBlockCipherMac(
                    new DESedeEngine());
            DESedeParameters keyParameters = new DESedeParameters(macKey);
            DESedeEngine engine = new DESedeEngine();
            engine.init(true, keyParameters);
            macCipher.init(keyParameters);
            macCipher.update(macDataBytes, 0, macData.length());
            macCipher.doFinal(macBytes, 0);
            encodedMacBytes = Hex.encode(macBytes);
            String mac = new String(encodedMacBytes);
            return mac;
        }
    }

    private static byte[] generateKey() {
        SecureRandom sr = new SecureRandom();
        KeyGenerationParameters kgp = new KeyGenerationParameters(sr, DESedeParameters.DES_KEY_LENGTH * 16);
        DESedeKeyGenerator kg = new DESedeKeyGenerator();
        kg.init(kgp);

        byte[] desKeyBytes = kg.generateKey();
        DESedeParameters.setOddParity(desKeyBytes);

        return desKeyBytes;
    }
    
    private static String getMACDataVersion9(HashMap<String, String> transactionParameters) 
    {
    	String macData = "";
    	
        if (transactionParameters.get(Interswitch.TID) != null) {
            macData += transactionParameters.get(Interswitch.TID);
        }
        
		 if (transactionParameters.get(Interswitch.PHONE_NUM) != null) {
	         macData += transactionParameters.get(Interswitch.PHONE_NUM);
	     }
		 
        if (transactionParameters.get(Interswitch.CARD_NAME) != null) {
            macData += transactionParameters.get(Interswitch.CARD_NAME);
        }

        if (transactionParameters.get(Interswitch.TTID) != null) {
            macData += transactionParameters.get(Interswitch.TTID);
        }

        if (transactionParameters.get(Interswitch.AMT) != null) {
            macData += transactionParameters.get(Interswitch.AMT);
        }
        
		 if (transactionParameters.get(Interswitch.TO_ACCT_NO) != null) {
	         macData += transactionParameters.get(Interswitch.TO_ACCT_NO);
	     }
	
		 if (transactionParameters.get(Interswitch.TO_BANK_CODE) != null) {
	         macData += transactionParameters.get(Interswitch.TO_BANK_CODE);
	     }
		 if (transactionParameters.get(Interswitch.CUST_NUM) != null) {
	         macData += transactionParameters.get(Interswitch.CUST_NUM);
	     }
		 
		 if (transactionParameters.get(Interswitch.BILL_CODE) != null) {
	         macData += transactionParameters.get(Interswitch.BILL_CODE);
	     }
		 
		 if (transactionParameters.get(Interswitch.TO_PHONE_NUM) != null) {
	         macData += transactionParameters.get(Interswitch.TO_PHONE_NUM);
	     }
		 
		 if (transactionParameters.get(Interswitch.PRODUCT_CODE) != null) {
	         macData += transactionParameters.get(Interswitch.PRODUCT_CODE);
	     }

        return macData;
    }

	public static String getMacData(HashMap<String, String> additionalSecureData) {
		String macData = getMACDataVersion9(additionalSecureData);
		byte[] macKey = new byte[16];
		return getMAC(macData, macKey, 12);
	}
}
