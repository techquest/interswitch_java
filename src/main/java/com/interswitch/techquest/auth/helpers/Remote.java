package com.interswitch.techquest.auth.helpers;

import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import javax.net.ssl.HttpsURLConnection;

import com.interswitch.techquest.auth.Interswitch;

public class Remote {

	public static HashMap<String, String> sendGET(String resourceUrl,HashMap<String, String> interswitchAuth) throws Exception 
	{
		HashMap<String, String> responseMap = new HashMap<String, String>();
		URL obj = new URL(resourceUrl);
		HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
		
		con.setRequestMethod("GET");
		con.setRequestProperty("Authorization",interswitchAuth.get(Interswitch.AUTHORIZATION));
		con.setRequestProperty("Timestamp", interswitchAuth.get(Interswitch.TIMESTAMP));
		con.setRequestProperty("Nonce", interswitchAuth.get(Interswitch.NONCE));
		con.setRequestProperty("Signature", interswitchAuth.get(Interswitch.SIGNATURE));
		con.setRequestProperty("SignatureMethod",interswitchAuth.get(Interswitch.SIGNATURE_METHOD));
		
		int responseCode = con.getResponseCode();
		
		InputStream inputStream;
		StringBuffer response = new StringBuffer();
		int c;
		try
		{
			inputStream = con.getInputStream();
		}
		catch(Exception ex)
		{
		
			inputStream = con.getErrorStream();

		}
		while ((c = inputStream.read()) != -1) {
			response.append((char) c);
		}
		
		responseMap.put(Interswitch.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(Interswitch.RESPONSE_MESSAGE, response.toString());
		
		
		return responseMap;
	}
	
	public static HashMap<String, String> sendGET(String resourceUrl,HashMap<String, String> interswitchAuth, HashMap<String, String> extraHeaders) throws Exception 
	{
	
		HashMap<String, String> responseMap = new HashMap<String, String>();
		URL obj = new URL(resourceUrl);
		HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
		//HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		
		con.setRequestMethod("GET");
		con.setRequestProperty("Authorization",interswitchAuth.get(Interswitch.AUTHORIZATION));
		con.setRequestProperty("Timestamp", interswitchAuth.get(Interswitch.TIMESTAMP));
		con.setRequestProperty("Nonce", interswitchAuth.get(Interswitch.NONCE));
		con.setRequestProperty("Signature", interswitchAuth.get(Interswitch.SIGNATURE));
		con.setRequestProperty("SignatureMethod",interswitchAuth.get(Interswitch.SIGNATURE_METHOD));
		
		if(extraHeaders != null && extraHeaders.size()>0)
		{
			Iterator<?> it = extraHeaders.entrySet().iterator();
		    while (it.hasNext()) {
		        Entry<String, String> pair = (Entry<String, String>)it.next();
		        con.setRequestProperty(pair.getKey(),pair.getValue());
		    }
		}
		
		int responseCode = con.getResponseCode();
		
		InputStream inputStream;
		StringBuffer response = new StringBuffer();
		int c;
		try
		{
			inputStream = con.getInputStream();
		}
		catch(Exception ex)
		{
		
		 inputStream = con.getErrorStream();

		}
		while ((c = inputStream.read()) != -1) {
			response.append((char) c);
		}
		
		responseMap.put(Interswitch.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(Interswitch.RESPONSE_MESSAGE, response.toString());
		
		
		return responseMap;
	}
	
	public static HashMap<String, String> sendPOST(String jsonText, String resourceUrl, HashMap<String, String> interswitchAuth)throws Exception
	{	
		HashMap<String, String> responseMap = new HashMap<String, String>();
		
		URL obj = new URL(resourceUrl);
		HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Authorization", interswitchAuth.get(Interswitch.AUTHORIZATION));
		con.setRequestProperty("Timestamp", interswitchAuth.get(Interswitch.TIMESTAMP));
		con.setRequestProperty("Nonce", interswitchAuth.get(Interswitch.NONCE));
		con.setRequestProperty("Signature", interswitchAuth.get(Interswitch.SIGNATURE));
		con.setRequestProperty("SignatureMethod", interswitchAuth.get(Interswitch.SIGNATURE_METHOD));

		con.setDoOutput(true);
		con.setRequestProperty("Content-Type", "application/json");
		
		OutputStreamWriter wr= new OutputStreamWriter(con.getOutputStream());
		wr.write(jsonText.toString());
		wr.close();
		
		int responseCode = con.getResponseCode();
		
		InputStream inputStream;
		StringBuffer response = new StringBuffer();
		int c;
		try
		{
			inputStream = con.getInputStream();
		}
		catch(Exception ex)
		{
		
		 inputStream = con.getErrorStream();

		}
		while ((c = inputStream.read()) != -1) {
			response.append((char) c);
		}
		
		responseMap.put(Interswitch.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(Interswitch.RESPONSE_MESSAGE, response.toString());
		
		return responseMap;
	}
	
	public static HashMap<String, String> sendPOST(String jsonText, String resourceUrl, HashMap<String, String> interswitchAuth, HashMap<String, String> extraHeaders)throws Exception
	{
		HashMap<String, String> responseMap = new HashMap<String, String>();
		
		URL obj = new URL(resourceUrl);
		//HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Authorization", interswitchAuth.get(Interswitch.AUTHORIZATION));
		con.setRequestProperty("Timestamp", interswitchAuth.get(Interswitch.TIMESTAMP));
		con.setRequestProperty("Nonce", interswitchAuth.get(Interswitch.NONCE));
		con.setRequestProperty("Signature", interswitchAuth.get(Interswitch.SIGNATURE));
		con.setRequestProperty("SignatureMethod", interswitchAuth.get(Interswitch.SIGNATURE_METHOD));

		con.setDoOutput(true);
		con.setRequestProperty("Content-Type", "application/json");
		
		if(extraHeaders != null && extraHeaders.size()>0)
		{
			Iterator<?> it = extraHeaders.entrySet().iterator();
		    while (it.hasNext()) {
		        Entry<String, String> pair = (Entry<String, String>)it.next();
		        con.setRequestProperty(pair.getKey(),pair.getValue());
		    }
		}
		
		OutputStreamWriter wr= new OutputStreamWriter(con.getOutputStream());
		wr.write(jsonText.toString());
		wr.close();
		
		int responseCode = con.getResponseCode();
		
		InputStream inputStream;
		StringBuffer response = new StringBuffer();
		int c;
		try
		{
			inputStream = con.getInputStream();
		}
		catch(Exception ex)
		{
		
		 inputStream = con.getErrorStream();

		}
		while ((c = inputStream.read()) != -1) {
			response.append((char) c);
		}
		
		responseMap.put(Interswitch.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(Interswitch.RESPONSE_MESSAGE, response.toString());
		
		return responseMap;
	}
	
//	private static javax.net.ssl.SSLSocketFactory getSSLFactory() throws Exception
//	{
//		
//		KeyStore keyStore =  KeyStore.getInstance(KeyStore.getDefaultType());
//		keyStore.load(new FileInputStream(Interswitch.CERT_PATH), "password".toCharArray());
//		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//		tmf.init(keyStore);
//		SSLContext ctx = SSLContext.getInstance("TLS");
//		ctx.init(null, tmf.getTrustManagers(), null);
//		javax.net.ssl.SSLSocketFactory sslFactory = ctx.getSocketFactory();
//		return sslFactory;
//	}
	
}
