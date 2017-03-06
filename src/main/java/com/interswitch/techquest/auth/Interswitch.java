package com.interswitch.techquest.auth;

import java.util.HashMap;

import com.interswitch.techquest.auth.helpers.Passport;
import com.interswitch.techquest.auth.helpers.Remote;
import com.interswitch.techquest.auth.helpers.RequestHeaders;
import com.interswitch.techquest.auth.helpers.TransactionSecurity;

public class Interswitch {

    public static final String ENV_SANDBOX = "SANDBOX";
    public static final String ENV_PROD = "PRODUCTION";
    public static final String ENV_DEV = "DEVELOPMENT";
    

    public static final String SANDBOX_BASE_URL = "https://sandbox.interswitchng.com/";
    public static final String PRODUCTION_BASE_URL = "https://saturn.interswitchng.com/";
    private static final String DEV_BASE_URL = "https://qa.interswitchng.com/";
    public static final String PASSPORT_RESOURCE_URL = "passport/oauth/token";

    public static final String TIMESTAMP = "TIMESTAMP";
    public static final String NONCE = "NONCE";
    public static final String SIGNATURE_METHOD = "SIGNATURE_METHOD";
    public static final String SIGNATURE = "SIGNATURE";
    public static final String AUTHORIZATION = "AUTHORIZATION";
    public static final String SIGNATURE_METHOD_VALUE = "SHA-512";
    public static final String LAGOS_TIME_ZONE = "Africa/Lagos";

    public static final String ISWAUTH_AUTHORIZATION_REALM = "InterswitchAuth";
    public static final String BEARER_AUTHORIZATION_REALM = "Bearer";
    public static final String ISO_8859_1 = "ISO-8859-1";

    public static final String RESPONSE_CODE = "RESPONSE_CODE";
    public static final String RESPONSE_MESSAGE = "RESPONSE_MESSAGE";

    public static final String ACCESS_TOKEN = "access_token";

    public static final String AUTH_DATA_VERSION = "1";

    public static final String SECURE = "SECURE";
    public static final String PINBLOCK = "PINBLOCK";

    public static final String TERMINAL_ID = "TerminalId";

    public static final String TID = "tid";
    public static final String CARD_NAME = "cardName";
    public static final String TTID = "ttid";
    public static final String AMT = "amt";
    public static final String TO_ACCT_NO = "toAcctNo";
    public static final String TO_BANK_CODE = "toBankCode";
    public static final String PHONE_NUM = "msisdn";
    public static final String CUST_NUM = "custNum";
    public static final String BILL_CODE = "billCode";
    public static final String TO_PHONE_NUM = "tPhoneNo";
    public static final String PRODUCT_CODE = "productCode";
    

    String clientId;
    String clientSecret;
    String environment;
    String baseUrl;
    String interswitchBaseUrl;

    public Interswitch(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.environment = Interswitch.ENV_SANDBOX;
        this.baseUrl = Interswitch.SANDBOX_BASE_URL;
    }

    public Interswitch(String clientId, String clientSecret, String environment) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.environment = environment;

        if (environment.equalsIgnoreCase(Interswitch.ENV_PROD)) {
            this.baseUrl = Interswitch.PRODUCTION_BASE_URL;
        } 
        else if(environment.equalsIgnoreCase(Interswitch.ENV_DEV)){
            this.baseUrl = Interswitch.DEV_BASE_URL;
        }else {
            this.baseUrl = Interswitch.SANDBOX_BASE_URL;
        }
    }
    
    public String getPassportUrl(String env) {
        if(env.equalsIgnoreCase(ENV_PROD)) {
            return PRODUCTION_BASE_URL;
        }
        else if(env.equalsIgnoreCase(ENV_SANDBOX)){
            return SANDBOX_BASE_URL;
        }
        else if(env.equalsIgnoreCase(ENV_DEV)){
            return DEV_BASE_URL;
        }
        else {
            return null;
        }
    }

    public HashMap<String, String> getSecureData(String pan, String expDate, String cvv, String pin) throws Exception {
        TransactionSecurity transactionSecurity = new TransactionSecurity();
        String publicExponent = "010001";
        String publicModulus = "009c7b3ba621a26c4b02f48cfc07ef6ee0aed8e12b4bd11c5cc0abf80d5206be69e1891e60fc88e2d565e2fabe4d0cf630e318a6c721c3ded718d0c530cdf050387ad0a30a336899bbda877d0ec7c7c3ffe693988bfae0ffbab71b25468c7814924f022cb5fda36e0d2c30a7161fa1c6fb5fbd7d05adbef7e68d48f8b6c5f511827c4b1c5ed15b6f20555affc4d0857ef7ab2b5c18ba22bea5d3a79bd1834badb5878d8c7a4b19da20c1f62340b1f7fbf01d2f2e97c9714a9df376ac0ea58072b2b77aeb7872b54a89667519de44d0fc73540beeaec4cb778a45eebfbefe2d817a8a8319b2bc6d9fa714f5289ec7c0dbc43496d71cf2a642cb679b0fc4072fd2cf";
        return transactionSecurity.getSecureData(publicExponent, publicModulus, pan, expDate, cvv, pin);
    }

    public HashMap<String, String> getSecureData(String pan, String expDate, String cvv, String pin, String publicCert) throws Exception {
        TransactionSecurity transactionSecurity = new TransactionSecurity();
        return transactionSecurity.getSecureData(publicCert, pan, expDate, cvv, pin);
    }

    public HashMap<String, String> getSecureData(String pan, String expDate, String cvv, String pin, HashMap<String, String> transactionParameters, String publicCert) throws Exception {
        TransactionSecurity transactionSecurity = new TransactionSecurity();
        return transactionSecurity.getSecureData(publicCert, pan, expDate, cvv, pin, transactionParameters);
    }

    public HashMap<String, String> getSecureData(String pan, String expDate, String cvv, String pin, String publicExponent, String publicModulus) throws Exception {
        TransactionSecurity transactionSecurity = new TransactionSecurity();
        return transactionSecurity.getSecureData(publicExponent, publicModulus, pan, expDate, cvv, pin);
    }

    public HashMap<String, String> getSecureData(String pan, String expDate, String cvv, String pin, HashMap<String, String> transactionParameters, String publicExponent, String publicModulus) throws Exception {
        TransactionSecurity transactionSecurity = new TransactionSecurity();
        return transactionSecurity.getSecureData(publicExponent, publicModulus, pan, expDate, cvv, pin, transactionParameters);
    }

    // Send to Remote uri,httpMethod,jsonData
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, baseUrl);

        String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);

        if (responseCode.equalsIgnoreCase("200")) {
            HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), url, httpMethod);
            if (httpMethod.equalsIgnoreCase("GET")) {
                return Remote.sendGET(url, headers);
            } else if (httpMethod.equalsIgnoreCase("POST")) {
                return Remote.sendPOST(jsonData, url, headers);
            }
        }

        return accessToken;
    }

    // Send to Remote uri,httpMethod,jsonData,additonalSignedParameters,extraHttpHeaders
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData, String additonalSignedParameters, HashMap<String, String> extraHttpHeaders) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, baseUrl);

        String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);

        if (responseCode.equalsIgnoreCase("200")) {
            HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), url, httpMethod);
            if (httpMethod.equalsIgnoreCase("GET")) {
                return Remote.sendGET(url, headers, extraHttpHeaders);
            } else if (httpMethod.equalsIgnoreCase("POST")) {
                return Remote.sendPOST(jsonData, url, headers, extraHttpHeaders);
            }
        }

        return accessToken;
    }

    // Send to Remote uri,httpMethod,jsonData,extraHttpHeaders
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData, HashMap<String, String> extraHttpHeaders) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, this.getPassportUrl(this.environment));

        String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);

        if (responseCode.equalsIgnoreCase("200")) {
            HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), url, httpMethod);
            if (httpMethod.equalsIgnoreCase("GET")) {
                return Remote.sendGET(url, headers, extraHttpHeaders);
            } else if (httpMethod.equalsIgnoreCase("POST")) {
                return Remote.sendPOST(jsonData, url, headers, extraHttpHeaders);
            }
        }

        return accessToken;
    }

    // Send to Remote uri,httpMethod,jsonData,additonalSignedParameters
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData, String signedParameters) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, baseUrl);

        String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);

        if (responseCode.equalsIgnoreCase("200")) {
            HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), url, httpMethod, signedParameters);
            if (httpMethod.equalsIgnoreCase("GET")) {
                return Remote.sendGET(url, headers);
            } else if (httpMethod.equalsIgnoreCase("POST")) {
                return Remote.sendPOST(jsonData, url, headers);
            }
        }

        return accessToken;
    }

    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, uri, httpMethod);
        if (httpMethod.equalsIgnoreCase("GET")) {
            return Remote.sendGET(url, headers);
        } else if (httpMethod.equalsIgnoreCase("POST")) {
            return Remote.sendPOST(data, url, headers);
        }

        return null;
    }

    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken, String signedParameters) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, url, httpMethod, signedParameters);
        if (httpMethod.equalsIgnoreCase("GET")) {
            return Remote.sendGET(url, headers);
        } else if (httpMethod.equalsIgnoreCase("POST")) {
            return Remote.sendPOST(data, url, headers);
        }
        return null;
    }

    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken, HashMap<String, String> httpHeaders) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, url, httpMethod);
        if (httpMethod.equalsIgnoreCase("GET")) {
            Remote.sendGET(url, headers, httpHeaders);
        } else if (httpMethod.equalsIgnoreCase("POST")) {
            Remote.sendPOST(data, url, headers, httpHeaders);
        }
        return null;
    }

    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken, HashMap<String, String> httpHeaders, String signedParameters) throws Exception {
        String url = baseUrl + uri;
        HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, url, httpMethod, signedParameters);
        if (httpMethod.equalsIgnoreCase("GET")) {
            Remote.sendGET(url, headers, httpHeaders);
        } else if (httpMethod.equalsIgnoreCase("POST")) {
            Remote.sendPOST(data, url, headers, httpHeaders);
        }
        return null;
    }

    public String getAuthData(String publicCert, String pan, String expDate, String cvv, String pin) throws Exception {
        return TransactionSecurity.getAuthData(publicCert, Interswitch.AUTH_DATA_VERSION, pan, expDate, cvv, pin);
    }

    public String getAuthData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin) throws Exception {
        return TransactionSecurity.getAuthData(publicExponent, publicModulus, Interswitch.AUTH_DATA_VERSION, pan, expDate, cvv, pin);
    }

    public String getMacData(HashMap<String, String> additionalSecureData) throws Exception {
        return TransactionSecurity.getMacData(additionalSecureData);
    }

}
