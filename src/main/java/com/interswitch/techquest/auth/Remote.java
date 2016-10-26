package com.interswitch.techquest.auth;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;

import com.interswitch.techquest.auth.utils.ConstantUtils;

public class Remote {

	public static HashMap<String, String> sendGET(String resourceUrl,HashMap<String, String> interswitchAuth) throws Exception 
	{
	
		HashMap<String, String> responseMap = new HashMap<String, String>();
	
		URL obj = new URL(resourceUrl);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("GET");
		con.setRequestProperty("Authorization",interswitchAuth.get(ConstantUtils.AUTHORIZATION));
		con.setRequestProperty("Timestamp", interswitchAuth.get(ConstantUtils.TIMESTAMP));
		con.setRequestProperty("Nonce", interswitchAuth.get(ConstantUtils.NONCE));
		con.setRequestProperty("Signature", interswitchAuth.get(ConstantUtils.SIGNATURE));
		con.setRequestProperty("SignatureMethod",interswitchAuth.get(ConstantUtils.SIGNATURE_METHOD));
		
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
		
		responseMap.put(ConstantUtils.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(ConstantUtils.RESPONSE_MESSAGE, response.toString());
		
		
		return responseMap;
	}
	
	public static HashMap<String, String> sendGET(String resourceUrl,HashMap<String, String> interswitchAuth, HashMap<String, String> extraHeaders) throws Exception 
	{
	
		HashMap<String, String> responseMap = new HashMap<String, String>();
	
		URL obj = new URL(resourceUrl);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("GET");
		con.setRequestProperty("Authorization",interswitchAuth.get(ConstantUtils.AUTHORIZATION));
		con.setRequestProperty("Timestamp", interswitchAuth.get(ConstantUtils.TIMESTAMP));
		con.setRequestProperty("Nonce", interswitchAuth.get(ConstantUtils.NONCE));
		con.setRequestProperty("Signature", interswitchAuth.get(ConstantUtils.SIGNATURE));
		con.setRequestProperty("SignatureMethod",interswitchAuth.get(ConstantUtils.SIGNATURE_METHOD));
		
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
		
		responseMap.put(ConstantUtils.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(ConstantUtils.RESPONSE_MESSAGE, response.toString());
		
		
		return responseMap;
	}
	
	public static HashMap<String, String> sendPOST(String jsonText, String resourceUrl, HashMap<String, String> interswitchAuth)throws Exception
	{
		HashMap<String, String> responseMap = new HashMap<String, String>();
		
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(resourceUrl);

		post.setHeader("Authorization", interswitchAuth.get(ConstantUtils.AUTHORIZATION));
		post.setHeader("Timestamp", interswitchAuth.get(ConstantUtils.TIMESTAMP));
		post.setHeader("Nonce", interswitchAuth.get(ConstantUtils.NONCE));
		post.setHeader("Signature", interswitchAuth.get(ConstantUtils.SIGNATURE));
		post.setHeader("SignatureMethod", interswitchAuth.get(ConstantUtils.SIGNATURE_METHOD));
		
		StringEntity entity = new StringEntity(jsonText);
		entity.setContentType("application/json");
		post.setEntity(entity);

		HttpResponse response = client.execute(post);
		int responseCode = response.getStatusLine().getStatusCode();
		HttpEntity httpEntity = response.getEntity();
		StringBuffer stringBuffer = new StringBuffer();
		if(httpEntity != null){
			InputStream inputStream = httpEntity.getContent();
			

			int c;
			while ((c = inputStream.read()) != -1) {
				stringBuffer.append((char) c);
			}
		}
		
		responseMap.put(ConstantUtils.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(ConstantUtils.RESPONSE_MESSAGE, stringBuffer.toString());
		
		
		return responseMap;
	}
	
	public static HashMap<String, String> sendPOST(String jsonText, String resourceUrl, HashMap<String, String> interswitchAuth, HashMap<String, String> extraHeaders)throws Exception
	{
		HashMap<String, String> responseMap = new HashMap<String, String>();
		
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(resourceUrl);

		post.setHeader("Authorization", interswitchAuth.get(ConstantUtils.AUTHORIZATION));
		post.setHeader("Timestamp", interswitchAuth.get(ConstantUtils.TIMESTAMP));
		post.setHeader("Nonce", interswitchAuth.get(ConstantUtils.NONCE));
		post.setHeader("Signature", interswitchAuth.get(ConstantUtils.SIGNATURE));
		post.setHeader("SignatureMethod", interswitchAuth.get(ConstantUtils.SIGNATURE_METHOD));
		
		if(extraHeaders != null && extraHeaders.size()>0)
		{
			Iterator<?> it = extraHeaders.entrySet().iterator();
		    while (it.hasNext()) {
		        Entry<String, String> pair = (Entry<String, String>)it.next();
		        post.setHeader(pair.getKey(),pair.getValue());
		    }
		}
		
		StringEntity entity = new StringEntity(jsonText);
		entity.setContentType("application/json");
		post.setEntity(entity);

		HttpResponse response = client.execute(post);
		int responseCode = response.getStatusLine().getStatusCode();
		HttpEntity httpEntity = response.getEntity();
		StringBuffer stringBuffer = new StringBuffer();
		if(httpEntity != null){
			InputStream inputStream = httpEntity.getContent();
			

			int c;
			while ((c = inputStream.read()) != -1) {
				stringBuffer.append((char) c);
			}
		}
		
		responseMap.put(ConstantUtils.RESPONSE_CODE, String.valueOf(responseCode));
		responseMap.put(ConstantUtils.RESPONSE_MESSAGE, stringBuffer.toString());
		
		
		return responseMap;
	}

}
