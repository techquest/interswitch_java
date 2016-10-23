package com.interswitch.techquest.secure.utils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AuthData {

	
	public static String generateAuthData(String version, String pan, String pin, String expiryDate, String cvv2) throws Exception
	{
		String authData = "";
		String authDataCipher = version + "Z" + pan + "Z" + pin + "Z" + expiryDate + "Z" + cvv2;
		System.out.println("Auth Data Cipher: " + authDataCipher);
		
		// The Modulus and Public Exponent will be supplied by Interswitch. please ask for one
		String modulus = "9c7b3ba621a26c4b02f48cfc07ef6ee0aed8e12b4bd11c5cc0abf80d5206be69e1891e60fc88e2d565e2fabe4d0cf630e318a6c721c3ded718d0c530cdf050387ad0a30a336899bbda877d0ec7c7c3ffe693988bfae0ffbab71b25468c7814924f022cb5fda36e0d2c30a7161fa1c6fb5fbd7d05adbef7e68d48f8b6c5f511827c4b1c5ed15b6f20555affc4d0857ef7ab2b5c18ba22bea5d3a79bd1834badb5878d8c7a4b19da20c1f62340b1f7fbf01d2f2e97c9714a9df376ac0ea58072b2b77aeb7872b54a89667519de44d0fc73540beeaec4cb778a45eebfbefe2d817a8a8319b2bc6d9fa714f5289ec7c0dbc43496d71cf2a642cb679b0fc4072fd2cf";
		String publicExponent = "010001";
		
		PublicKey publicKey = getPublicKey(modulus, publicExponent);
		Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] authDataBytes = encryptCipher.doFinal(authDataCipher.getBytes("UTF8"));
		authData = new String(org.bouncycastle.util.encoders.Base64.encode(authDataBytes)).trim();
		return authData;
	}
	
	public static PublicKey getPublicKey(String modulus, String publicExponent)  throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		RSAPublicKeySpec publicKeyspec = new RSAPublicKeySpec(new BigInteger(modulus, 16), new BigInteger(publicExponent, 16));
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = factory.generatePublic(publicKeyspec);
		return publicKey;
	}
}
