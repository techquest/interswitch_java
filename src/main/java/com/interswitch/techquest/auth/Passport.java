package com.interswitch.techquest.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Abiola.Adebanjo
 */
public class Passport {

    public static String getClientAccessToken(String clientId, String clientSecret, String passportUrl) throws Exception {
        URL obj = new URL(passportUrl);

        System.setProperty("http.maxRedirects", "100");
        java.net.CookieManager cm = new java.net.CookieManager();
        java.net.CookieHandler.setDefault(cm);

        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        String basicAuthCipher = clientId + ":" + clientSecret;
        String basicAuth = new String(Base64.encode(basicAuthCipher.getBytes()));

        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Authorization", "Basic " + basicAuth);
        String request = "grant_type=client_credentials";

        con.setDoOutput(true);
        DataOutputStream wr = new DataOutputStream(con.getOutputStream());
        wr.writeBytes(request);
        wr.flush();
        wr.close();

        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        } catch (Exception ex) {
            in = new BufferedReader(new InputStreamReader(con.getErrorStream()));
        }

        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        int responseCode = con.getResponseCode();
        if (responseCode == 200) {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, String> map = new HashMap<String, String>();
            map = mapper.readValue(response.toString(),
                    new TypeReference<Map<String, String>>() {
            });

            String accesToken = map.get("access_token");

            return accesToken;
        }

        return null;
    }
}
