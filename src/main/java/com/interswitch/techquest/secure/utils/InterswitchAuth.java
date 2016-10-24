package com.interswitch.techquest.secure.utils;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
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
    private static final String ISO_8859_1 = "ISO-8859-1";

    public static HashMap<String, String> generateInterswitchAuth(String httpMethod, String resourceUrl, String clientId, String clientSecretKey, String additionalParameters, String signatureMethod) throws Exception {
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
        if (additionalParameters != null && !"".equals(additionalParameters)) {
            signatureCipher = signatureCipher + "&" + additionalParameters;
        }
        // System.out.println(signatureCipher);
        MessageDigest messageDigest = MessageDigest
                .getInstance(signatureMethod);
        byte[] signatureBytes = messageDigest
                .digest(signatureCipher.getBytes());

        // encode signature as base 64
        String signature = new String(Base64.encodeBase64(signatureBytes));

        interswitchAuth.put(AUTHORIZATION, authorization);
        interswitchAuth.put(TIMESTAMP, String.valueOf(timestamp));
        interswitchAuth.put(NONCE, nonce);
        interswitchAuth.put(SIGNATURE_METHOD, signatureMethod);
        interswitchAuth.put(SIGNATURE, signature);

        return interswitchAuth;
    }

    public static String getAccessToken(String clientId, String clientSecret, String passportUrl) throws Exception {
        URL obj = new URL(passportUrl);

        System.setProperty("http.maxRedirects", "100");
        java.net.CookieManager cm = new java.net.CookieManager();
        java.net.CookieHandler.setDefault(cm);

        System.out.println("\nSending 'POST' request to URL : "
                + passportUrl);
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

        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> map = new HashMap<String, String>();
        map = mapper.readValue(response.toString(),
                new TypeReference<Map<String, String>>() {
        });

        String accesToken = map.get("access_token");
        System.out.println("Access Token: " + accesToken);
        
        return accesToken;
    }

}
