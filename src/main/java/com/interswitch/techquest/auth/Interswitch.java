package com.interswitch.techquest.auth;

import java.util.HashMap;

import com.interswitch.techquest.auth.utils.ConstantUtils;

public class Interswitch {
	
    String clientId;
    String clientSecret;
    String environment;
    String passportBaseUrl;
    
    public Interswitch(String clientId,String clientSecret) {
    	this.clientId = clientId;
    	this.clientSecret = clientSecret;
    	this.environment = ConstantUtils.ENV_SANDBOX;
    	this.passportBaseUrl = ConstantUtils.SANDBOX_BASE_URL;
	}
    public Interswitch(String clientId,String clientSecret,String environment) {
    	this.clientId = clientId;
    	this.clientSecret = clientSecret;
    	this.environment = environment;
    	
    	if(environment.equalsIgnoreCase(ConstantUtils.ENV_PROD))
    	{
    		this.passportBaseUrl = ConstantUtils.PRODUCTION_BASE_URL;
    	}
    	else
    	{
    		this.passportBaseUrl = ConstantUtils.SANDBOX_BASE_URL;
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

    public HashMap<String, String> send(String uri, String httpMethod, String data) throws Exception
    {
    	String accessToken = Passport.getClientAccessToken(clientId, clientSecret, passportBaseUrl);
    	HashMap<String, String> headers = RequestHeaders.getBearerSecurityHeaders(clientId, clientSecret, accessToken, uri, httpMethod);
    	if(httpMethod.equalsIgnoreCase("GET"))
    	{
    		Remote.sendGET(uri, headers);
    	}
    	else if (httpMethod.equalsIgnoreCase("POST"))
    	{
    		Remote.sendPOST(data, uri, headers);
    	}
    	return null;
    }
    public HashMap<String, String> send(String uri, String httpMethod, String data, String accessToken) throws Exception
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
    public HashMap<String, String> send(String uri, String httpMethod, String data, String accessToken, String signedParameters) throws Exception
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
    public HashMap<String, String> send(String uri, String httpMethod, String data, String accessToken, HashMap<String, String> httpHeaders) throws Exception
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
    
    public HashMap<String, String> send(String uri, String httpMethod, String data, String accessToken, HashMap<String, String> httpHeaders, String signedParameters) throws Exception
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
    	return TransactionSecurity.getAuthData(publicCert, ConstantUtils.AUTH_DATA_VERSION, pan, expDate, cvv, pin);
    }
    
    public String getAuthData(String publicExponent, String publicModulus, String pan, String expDate, String cvv, String pin) throws Exception
    {
    	return TransactionSecurity.getAuthData(publicExponent, publicModulus, ConstantUtils.AUTH_DATA_VERSION, pan, expDate, cvv, pin);
    }

}
