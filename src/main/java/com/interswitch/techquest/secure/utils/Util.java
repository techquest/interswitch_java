package com.interswitch.techquest.secure.utils;

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
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.KeyGenerationParameters;

import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Hex;

public class Util {

    public static RSAKeyParameters getRSAKeyParameters(String certFilePath) throws Exception {
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
        SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
        RSAKeyParameters rsaKeyParameters = (RSAKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);

        return rsaKeyParameters;
    }

    public static PublicKey getPublicKey(String certFilePath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyParameters rSAKeyParameters = getRSAKeyParameters(certFilePath);
        RSAPublicKeySpec publicKeyspec = new RSAPublicKeySpec(rSAKeyParameters.getModulus(), rSAKeyParameters.getExponent());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(publicKeyspec);

        return publicKey;
    }

    public static String getMACDataVersion9(String susbscriberID,
            String cardName, String transCode, String amt, String phoneNum,
            String custNum, String paymentItemCode) {
        String macData = "";
        if (susbscriberID != null && !susbscriberID.isEmpty()) {
            macData = macData + susbscriberID;
        }
        if (cardName != null && !cardName.isEmpty()) {
            macData = macData + cardName;
        }
        if (transCode != null && !transCode.isEmpty()) {
            macData = macData + transCode;
        }
        if (amt != null && !amt.isEmpty()) {
            macData = macData + amt;
        }
        if (phoneNum != null && !phoneNum.isEmpty()) {
            macData = macData + phoneNum;
        }
        if (custNum != null && !custNum.isEmpty()) {
            macData = macData + custNum;
        }
        if (paymentItemCode != null && !paymentItemCode.isEmpty()) {
            macData = macData + paymentItemCode;
        }
        return macData;
    }

    public static RSAKeyParameters getPublicSecureKey(String modulus,
            String exponent) {
        BigInteger modulusByte = new BigInteger(Hex.decode(modulus));
        BigInteger exponentByte = new BigInteger(Hex.decode(exponent));
        RSAKeyParameters pkParameters = new RSAKeyParameters(false,
                modulusByte, exponentByte);
        return pkParameters;
    }

    public static byte[] HexConverter(String str) {
        try {
            str = new String(str.getBytes(), StandardCharsets.UTF_8);
            byte[] myBytes = Hex.decode(str);
            return myBytes;
        } catch (Exception ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static String padRight(String data, int maxLen) {

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

    public static void zeroise(byte[] data) {
        int len = data.length;

        for (int i = 0; i < len; i++) {
            data[i] = 0;
        }
    }

    public static String getMAC(String macData, byte[] macKey, int macVersion) {
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

    public static byte[] generateKey() {
        SecureRandom sr = new SecureRandom();
        KeyGenerationParameters kgp = new KeyGenerationParameters(sr, DESedeParameters.DES_KEY_LENGTH * 16);
        DESedeKeyGenerator kg = new DESedeKeyGenerator();
        kg.init(kgp);

        byte[] desKeyBytes = kg.generateKey();
        DESedeParameters.setOddParity(desKeyBytes);

        return desKeyBytes;
    }

}
