package com.interswitch.techquest.secure.utils;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class InterswitchAuth {

	private static final String TIMESTAMP = "TIMESTAMP";
	private static final String NONCE = "NONCE";
	private static final String SIGNATURE_METHOD = "SIGNATURE_METHOD";
	private static final String SIGNATURE = "SIGNATURE";
	private static final String AUTHORIZATION = "AUTHORIZATION";

	private static final String AUTHORIZATION_REALM = "InterswitchAuth";
	private static final String AUTHORIZATION_REALM_BEARER = "Bearer";
	private static final String ISO_8859_1 = "ISO-8859-1";

	public static HashMap<String, String> generateInterswitchAuth(
			String httpMethod, String resourceUrl, String clientId,
			String clientSecretKey, String additionalParameters,
			String signatureMethod, String authType, String environment)
			throws Exception {
		HashMap<String, String> interswitchAuth = new HashMap<String, String>();

		// Timezone MUST be Africa/Lagos.
		TimeZone lagosTimeZone = TimeZone.getTimeZone("Africa/Lagos");

		Calendar calendar = Calendar.getInstance(lagosTimeZone);

		// Timestamp must be in seconds.
		long timestamp = calendar.getTimeInMillis() / 1000;

		UUID uuid = UUID.randomUUID();
		String nonce = uuid.toString().replaceAll("-", "");

		String clientIdBase64 = new String(Base64.encodeBase64(clientId
				.getBytes()));
		String authorization = AUTHORIZATION_REALM + " " + clientIdBase64;

		resourceUrl = resourceUrl.replace("http://", "https://");
		String encodedResourceUrl = URLEncoder.encode(resourceUrl, ISO_8859_1);
		String signatureCipher = httpMethod + "&" + encodedResourceUrl + "&"
				+ timestamp + "&" + nonce + "&" + clientId + "&"
				+ clientSecretKey;
		if (additionalParameters != null && !"".equals(additionalParameters))
			signatureCipher = signatureCipher + "&" + additionalParameters;
		// System.out.println(signatureCipher);
		MessageDigest messageDigest = MessageDigest
				.getInstance(signatureMethod);
		byte[] signatureBytes = messageDigest
				.digest(signatureCipher.getBytes());

		// encode signature as base 64
		String signature = new String(Base64.encodeBase64(signatureBytes));
		// System.out.println("Cipher: " + signatureCipher);
		if (authType.equalsIgnoreCase("oauth")) {
			String bearerAuthorization = getAccessToken(clientId,
					clientSecretKey, environment);
			interswitchAuth.put(AUTHORIZATION, AUTHORIZATION_REALM_BEARER + " "
					+ bearerAuthorization);
		} else {
			interswitchAuth.put(AUTHORIZATION, authorization);
		}

		interswitchAuth.put(TIMESTAMP, String.valueOf(timestamp));
		interswitchAuth.put(NONCE, nonce);
		interswitchAuth.put(SIGNATURE_METHOD, signatureMethod);
		interswitchAuth.put(SIGNATURE, signature);

		return interswitchAuth;
	}

	public static String getAccessToken(String clientId, String clientSecret,
			String environment) throws Exception {
		String PRODUCTION_PASSPORT_RESOURCE_URL = "https://passport.interswitchng.com/passport/oauth/token";
		String SANDBOX_PASSPORT_RESOURCE_URL = "http://sandbox.interswitchng.com/passport/oauth/token";
		String PASSPORT_RESOURCE_URL = "";

		if (environment.equalsIgnoreCase("live")) {
			PASSPORT_RESOURCE_URL = PRODUCTION_PASSPORT_RESOURCE_URL;
		} else {
			PASSPORT_RESOURCE_URL = SANDBOX_PASSPORT_RESOURCE_URL;
		}

		URL obj = new URL(PASSPORT_RESOURCE_URL);

		System.setProperty("http.maxRedirects", "100");
		java.net.CookieManager cm = new java.net.CookieManager();
		java.net.CookieHandler.setDefault(cm);

		System.out.println("\nSending 'POST' request to URL : "
				+ PASSPORT_RESOURCE_URL);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("POST");
		String basicAuthCipher = clientId + ":" + clientSecret;
		String basicAuth = new String(
				org.bouncycastle.util.encoders.Base64.encode(basicAuthCipher
						.getBytes()));
		System.out.println("\nBasic Auth : " + basicAuth);

		// // Set Headers
		con.setRequestProperty("Content-Type",
				"application/x-www-form-urlencoded");
		con.setRequestProperty("Authorization", "Basic " + basicAuth);
		String request = "grant_type=client_credentials";

		// Send post request
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(request);
		wr.flush();
		wr.close();

		int responseCode = con.getResponseCode();

		// System.out.println("Post parameters : " + request);
		System.out.println("Response Code : " + responseCode);
		BufferedReader in = null;
		try {
			in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		} catch (Exception ex) {
			ex.printStackTrace();
			in = new BufferedReader(new InputStreamReader(con.getErrorStream()));
		}

		String inputLine;
		StringBuffer response = new StringBuffer();
		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();
		// print result
		JSONObject jSONObjectx = new JSONObject(response.toString());
		System.out.println(jSONObjectx.toString(2));
		// System.out.println(response.toString());
		ObjectMapper mapper = new ObjectMapper();
		Map<String, String> map = new HashMap<String, String>();
		map = mapper.readValue(response.toString(),
				new TypeReference<Map<String, String>>() {
				});

		return map.get("access_token");
	}

	public static String generateTransactionAuthData(String version, String pan,
			String pin, String expiryDate, String cvv2,String modulus,String publicExponent) throws Exception {
		String authData = "";
		String authDataCipher = version + "Z" + pan + "Z" + pin + "Z"
				+ expiryDate + "Z" + cvv2;

		PublicKey publicKey = Util.getPublicKey(modulus, publicExponent);
		Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] authDataBytes = encryptCipher.doFinal(authDataCipher
				.getBytes("UTF8"));
		authData = new String(
				org.bouncycastle.util.encoders.Base64.encode(authDataBytes))
				.trim();
		return authData;
	}

	public static String getPINBlock(String pin, String cvv2, String expiryDate,
			byte[] keyBytes) {
		pin = null == pin || pin.equals("") ? "0000" : pin;
		cvv2 = null == cvv2 || cvv2.equals("") ? "000" : cvv2;
		expiryDate = null == expiryDate || expiryDate.equals("") ? "0000"
				: expiryDate;

		String pinBlockString = pin + cvv2 + expiryDate;
		int pinBlockStringLen = pinBlockString.length();
		String pinBlickLenLenString = String.valueOf(pinBlockStringLen);
		int pinBlickLenLen = pinBlickLenLenString.length();
		String clearPINBlock = String.valueOf(pinBlickLenLen)
				+ pinBlockStringLen + pinBlockString;

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
		byte[] encodedEncryptedPINBlockBytes = Hex
				.encode(encryptedPINBlockBytes);
		String pinBlock = new String(encodedEncryptedPINBlockBytes);

		pin = "0000000000000000";
		clearPINBlock = "0000000000000000";

		Util.zeroise(clearPINBlockBytes);
		Util.zeroise(encryptedPINBlockBytes);
		Util.zeroise(encodedEncryptedPINBlockBytes);

		return pinBlock;
	}

	public String getSecure(String publicKeyModulus, String publicKeyExponent,
			byte[] keyBytes, String pan) {
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

		headerBytes = Util.HexConverter("4D");
		formatVersionBytes = Util.HexConverter("10");
		macVersionBytes = Util.HexConverter("10");

		pinDesKey = keyBytes;

		if (pan != null) {
			int panDiff = 20 - pan.length();
			String panString = panDiff + pan;
			int panlen = 20 - panString.length();
			for (int i = 0; i < panlen; i++) {
				panString += "F";
			}

			customerIdBytes = Util.HexConverter(Util.padRight(panString, 20));

		}

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
		RSAKeyParameters publicKeyParameters = Util.getPublicSecureKey(
				publicKeyModulus, publicKeyExponent);
		engine.init(true, publicKeyParameters);
		byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0,
				secureBytes.length);
		byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
		String encrytedSecure = new String(encodedEncryptedSecureBytes);

		Util.zeroise(secureBytes);

		return encrytedSecure;
	}

	public static String getSecureV2(String publicKeyModulus,
			String publicKeyExponent, byte[] keyBytes, String pan,
			String susbscriberID, String transCode, String amt,
			String phoneNum, String custNum, String paymentItemCode,
			String cardName) {
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

		String macData = Util.getMACDataVersion9(susbscriberID, cardName,
				transCode, amt, phoneNum, custNum, paymentItemCode);
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
		RSAKeyParameters publicKeyParameters = Util.getPublicSecureKey(
				publicKeyModulus, publicKeyExponent);
		engine.init(true, publicKeyParameters);
		byte[] encryptedSecureBytes = engine.processBlock(secureBytes, 0,
				secureBytes.length);
		byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
		String encrytedSecure = new String(encodedEncryptedSecureBytes);

		Util.zeroise(secureBytes);

		return encrytedSecure;
	}

	public static byte[] generateKey() {
		SecureRandom sr = new SecureRandom();
		KeyGenerationParameters kgp = new KeyGenerationParameters(sr,
				DESedeParameters.DES_KEY_LENGTH * 16);
		DESedeKeyGenerator kg = new DESedeKeyGenerator();
		kg.init(kgp);

		byte[] desKeyBytes = kg.generateKey();
		DESedeParameters.setOddParity(desKeyBytes);

		return desKeyBytes;
	}
}
