package com.interswitch.techquest.auth;

import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Calendar;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;

import com.interswitch.techquest.auth.utils.ConstantUtils;

public class RequestHeaders {

	public static HashMap<String, String> getISWAuthSecurityHeaders(String clientId, String clientSecretKey, String resourceUrl, String httpMethod, String... transactionParams) throws Exception {
        HashMap<String, String> interswitchAuth = new HashMap<String, String>();

        long timestamp = generateTimestamp();
        String nonce = generateNonce();
        String signature = getSignature(clientId, clientSecretKey, resourceUrl, httpMethod, timestamp, nonce, transactionParams);

        String clientIdBase64 = new String(Base64.encodeBase64(clientId.getBytes()));
        String authorization = ConstantUtils.ISWAUTH_AUTHORIZATION_REALM + " " + clientIdBase64;

        interswitchAuth.put(ConstantUtils.AUTHORIZATION, authorization);
        interswitchAuth.put(ConstantUtils.TIMESTAMP, String.valueOf(timestamp));
        interswitchAuth.put(ConstantUtils.NONCE, nonce);
        interswitchAuth.put(ConstantUtils.SIGNATURE_METHOD, ConstantUtils.SIGNATURE_METHOD_VALUE);
        interswitchAuth.put(ConstantUtils.SIGNATURE, signature);

        return interswitchAuth;
    }

    public static HashMap<String, String> getBearerSecurityHeaders(String clientId, String clientSecretKey, String accessToken, String resourceUrl, String httpMethod, String... transactionParams) throws Exception {
        HashMap<String, String> interswitchAuth = new HashMap<String, String>();

        long timestamp = generateTimestamp();
        String nonce = generateNonce();
        String signature = getSignature(clientId, clientSecretKey, resourceUrl, httpMethod, timestamp, nonce, transactionParams);

        String authorization = ConstantUtils.BEARER_AUTHORIZATION_REALM + " " + accessToken;

        interswitchAuth.put(ConstantUtils.AUTHORIZATION, authorization);
        interswitchAuth.put(ConstantUtils.TIMESTAMP, String.valueOf(timestamp));
        interswitchAuth.put(ConstantUtils.NONCE, nonce);
        interswitchAuth.put(ConstantUtils.SIGNATURE_METHOD, ConstantUtils.SIGNATURE_METHOD_VALUE);
        interswitchAuth.put(ConstantUtils.SIGNATURE, signature);

        return interswitchAuth;
    }

    private static String getSignature(String clientId, String clientSecretKey, String resourceUrl, String httpMethod, long timestamp, String nonce, String... transactionParameters) throws Exception {
        String https = "https";
        String http = "http";
        if (!resourceUrl.toLowerCase().contains(https.subSequence(0, https.length()))) {
            resourceUrl = resourceUrl.replace(http, https);
        }
        resourceUrl = URLEncoder.encode(resourceUrl, ConstantUtils.ISO_8859_1);
        String signatureCipher = httpMethod + "&" + resourceUrl + "&" + timestamp + "&" + nonce + "&" + clientId + "&" + clientSecretKey;
        if (transactionParameters != null && transactionParameters.length > 0) {
            String transactionParameterTemp = "";
            for (String transactionParameter : transactionParameters) {
                if (transactionParameter != null && !transactionParameter.isEmpty()) {
                    transactionParameterTemp = "&" + transactionParameter;
                }
            }
            signatureCipher = signatureCipher + transactionParameterTemp;
        }

        MessageDigest messagedigest = MessageDigest.getInstance(ConstantUtils.SIGNATURE_METHOD_VALUE);
        byte[] signaturebytes = messagedigest.digest(signatureCipher.getBytes());
        String signature = new String(org.bouncycastle.util.encoders.Base64.encode(signaturebytes)).trim();
        return signature.replaceAll("\\s", "");
    }

    private static long generateTimestamp() {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone(ConstantUtils.LAGOS_TIME_ZONE));
        long epochTimeInSecs = calendar.getTimeInMillis() / 1000;
        return epochTimeInSecs;
    }

    private static String generateNonce() {
        UUID nonce = UUID.randomUUID();
        return nonce.toString().replaceAll("-", "");
    }
}
