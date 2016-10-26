package com.interswitch.techquest.auth;

import java.util.HashMap;

public class Interswitch {
	
	public static final String ENV_SANDBOX = "SANDBOX";
	public static final String ENV_PROD = "PRODUCTION";
	
	public static final String SANDBOX_BASE_URL = "http://172.35.2.6:7073/";//"https://sandbox.interswitchng.com/";
	public static final String PRODUCTION_BASE_URL = "https://saturn.interswitchng.com/";
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
    String passportBaseUrl;
    
    public Interswitch(String clientId,String clientSecret) {
    	this.clientId = clientId;
    	this.clientSecret = clientSecret;
    	this.environment = Interswitch.ENV_SANDBOX;
    	this.passportBaseUrl = Interswitch.SANDBOX_BASE_URL;
	}
    public Interswitch(String clientId,String clientSecret,String environment) {
    	this.clientId = clientId;
    	this.clientSecret = clientSecret;
    	this.environment = environment;
    	
    	if(environment.equalsIgnoreCase(Interswitch.ENV_PROD))
    	{
    		this.passportBaseUrl = Interswitch.PRODUCTION_BASE_URL;
    	}
    	else
    	{
    		this.passportBaseUrl = Interswitch.SANDBOX_BASE_URL;
    	}
	}
    
    public HashMap<String, String> getSecureData(String publicCert, String pan, String expDate, String cvv, String pin) throws Exception
    {
    	TransactionSecurity transactionSecurity = new TransactionSecurity();
    	return transactionSecurity.getSecureData(publicCert, pan, expDate, cvv, pin);
    }
    
    public HashMap<String, String> getSecureData(String publicCert, String pan, String expDate, String cvv, String pin,HashMap<String, String>transactionParameters) throws Exception
    {
    	TransactionSecurity transactionSecurity = new TransactionSecurity();
    	return transactionSecurity.getSecureData(publicCert, pan, expDate, cvv, pin,transactionParameters);
    }
    
    public HashMap<String, String> getSecureData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin) throws Exception
    {
    	TransactionSecurity transactionSecurity = new TransactionSecurity();
    	return transactionSecurity.getSecureData(publicExponent, publicModulus, pan, expDate, cvv, pin);
    }
    
    public HashMap<String, String> getSecureData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin,HashMap<String, String>transactionParameters) throws Exception
    {
    	TransactionSecurity transactionSecurity = new TransactionSecurity();
    	return transactionSecurity.getSecureData(publicExponent, publicModulus, pan, expDate, cvv, pin,transactionParameters);
    }

    //Send to Remote uri,httpMethod,jsonData
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData) throws Exception
    {
    	HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, passportBaseUrl);
    	
    	String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);
    	
    	if (responseCode.equalsIgnoreCase("200")) 
    	{
    		HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), uri, httpMethod);
        	if(httpMethod.equalsIgnoreCase("GET"))
        	{
        		return Remote.sendGET(uri, headers);
        	}
        	else if (httpMethod.equalsIgnoreCase("POST"))
        	{
        		return Remote.sendPOST(jsonData, uri, headers);
        	}
    	}
    	
    	return accessToken;
    }
  //Send to Remote uri,httpMethod,jsonData,additonalSignedParameters,extraHttpHeaders
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData,String additonalSignedParameters,HashMap<String, String> extraHttpHeaders) throws Exception
    {
    	HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, passportBaseUrl);
    	
    	String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);
    	
    	if (responseCode.equalsIgnoreCase("200")) 
    	{
    		HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), uri, httpMethod);
        	if(httpMethod.equalsIgnoreCase("GET"))
        	{
        		return Remote.sendGET(uri, headers,extraHttpHeaders);
        	}
        	else if (httpMethod.equalsIgnoreCase("POST"))
        	{
        		return Remote.sendPOST(jsonData, uri, headers,extraHttpHeaders);
        	}
    	}
    	
    	return accessToken;
    }
    //Send to Remote uri,httpMethod,jsonData,extraHttpHeaders
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData,HashMap<String, String> extraHttpHeaders) throws Exception
    {
    	HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, passportBaseUrl);
    	
    	String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);
    	
    	if (responseCode.equalsIgnoreCase("200")) 
    	{
    		HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), uri, httpMethod);
        	if(httpMethod.equalsIgnoreCase("GET"))
        	{
        		return Remote.sendGET(uri, headers,extraHttpHeaders);
        	}
        	else if (httpMethod.equalsIgnoreCase("POST"))
        	{
        		return Remote.sendPOST(jsonData, uri, headers,extraHttpHeaders);
        	}
    	}
    	
    	return accessToken;
    }
//    Send to Remote uri,httpMethod,jsonData,additonalSignedParameters
    public HashMap<String, String> send(String uri, String httpMethod, String jsonData,String signedParameters) throws Exception
    {
    	HashMap<String, String> accessToken = Passport.getClientAccessToken(clientId, clientSecret, passportBaseUrl);
    	
    	String responseCode = accessToken.get(Interswitch.RESPONSE_CODE);
    	
    	if (responseCode.equalsIgnoreCase("200")) 
    	{
    		HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken.get(Interswitch.ACCESS_TOKEN), uri, httpMethod,signedParameters);
        	if(httpMethod.equalsIgnoreCase("GET"))
        	{
        		return Remote.sendGET(uri, headers);
        	}
        	else if (httpMethod.equalsIgnoreCase("POST"))
        	{
        		return Remote.sendPOST(jsonData, uri, headers);
        	}
    	}
    	
    	return accessToken;
    }
    
    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken) throws Exception
    {
    	HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, uri, httpMethod);
    	if(httpMethod.equalsIgnoreCase("GET"))
    	{
    		return Remote.sendGET(uri, headers);
    	}
    	else if (httpMethod.equalsIgnoreCase("POST"))
    	{
    		return Remote.sendPOST(data, uri, headers);
    	}
    	
    	return null;
    }
    
    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken, String signedParameters) throws Exception
    {
    
    	HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, uri, httpMethod,signedParameters);
    	if(httpMethod.equalsIgnoreCase("GET"))
    	{
    		return Remote.sendGET(uri, headers);
    	}
    	else if (httpMethod.equalsIgnoreCase("POST"))
    	{
    		return Remote.sendPOST(data, uri, headers);
    	}
    	return null;
    }
    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken, HashMap<String, String> httpHeaders) throws Exception
    {
    	
    	HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, uri, httpMethod);
    	if(httpMethod.equalsIgnoreCase("GET"))
    	{
    		Remote.sendGET(uri, headers,httpHeaders);
    	}
    	else if (httpMethod.equalsIgnoreCase("POST"))
    	{
    		Remote.sendPOST(data, uri, headers,httpHeaders);
    	}
    	return null;
    }
    
    public HashMap<String, String> sendWithAccessToken(String uri, String httpMethod, String data, String accessToken, HashMap<String, String> httpHeaders, String signedParameters) throws Exception
    {
    
    	HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, uri, httpMethod,signedParameters);
    	if(httpMethod.equalsIgnoreCase("GET"))
    	{
    		Remote.sendGET(uri, headers,httpHeaders);
    	}
    	else if (httpMethod.equalsIgnoreCase("POST"))
    	{
    		Remote.sendPOST(data, uri, headers,httpHeaders);
    	}
    	return null;
    }
    
    public String getAuthData(String publicCert, String pan, String expDate, String cvv, String pin) throws Exception
    {
    	return TransactionSecurity.getAuthData(publicCert, Interswitch.AUTH_DATA_VERSION, pan, expDate, cvv, pin);
    }
    
    public String getAuthData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin) throws Exception
    {
    	return TransactionSecurity.getAuthData(publicExponent, publicModulus, Interswitch.AUTH_DATA_VERSION, pan, expDate, cvv, pin);
    }

}
