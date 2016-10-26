package com.interswitch.techquest.auth;

import java.util.HashMap;

import org.json.JSONObject;

import com.interswitch.techquest.auth.utils.ConstantUtils;

public class InterswitchTestDriver {

	static Interswitch interswitch = new Interswitch("IKIAF6C068791F465D2A2AA1A3FE88343B9951BAC9C3", "FTbMeBD7MtkGBQJw1XoM74NaikuPL13Sxko1zb0DMjI=");
	static Interswitch interswitchPayment = new Interswitch("IKIA9614B82064D632E9B6418DF358A6A4AEA84D7218", "XCTiBtLy1G9chAnyg0z3BcaFK4cVpwDg/GTw2EmjTZ8=");
	static String publicCertPath = "../ewallet/src/main/resources/paymentgateway.crt";
	public static void main(String[] args) throws Exception 
	{
		HashMap<String, String> interswitchResponse = new HashMap<String, String>();
		
//		interswitchResponse = getPaymentInstrument();
//		interswitchResponse = getQuicktellerBillers();
//		interswitchResponse = getQuicktellerBillersCategorys();
//		interswitchResponse = doTransactionInquiry();
//		interswitchResponse = sendTransaction();
//		interswitchResponse = doPayment();
//		interswitchResponse = getPaymentStatus();
//		interswitchResponse = getPaymentInstrumentEwallet();
		interswitchResponse = generatePaycode();
		
		
		String responseCode = interswitchResponse.get(Interswitch.RESPONSE_CODE);
		String responseMessage = interswitchResponse.get(Interswitch.RESPONSE_MESSAGE);
		
		System.out.println("HTTP Response Code "+ responseCode);
		System.out.println("Response Message "+ responseMessage);
	}

	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> getPaymentInstrument()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		String phoneNumber = "2348065186175";
		String scheme = ConstantUtils.SCHEME;
		String merchantid = ConstantUtils.MERCHANT_ID;
		String channel = ConstantUtils.CHANNEL;
		String version = ConstantUtils.VERSION;
		String transactionType = "getallpaymentmethods";
		String httpMethod = ConstantUtils.GET;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.VERVE_BASE_URL + phoneNumber+ "/paymentmethods.json?scheme=" + scheme + "&channel="
				+ channel + "&merchantid=" + merchantid + "&version=" + version
				+ "&transactionType=" + transactionType;
		
		interswitchResponse = interswitch.send(resourceUrl, httpMethod, null);
		
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> getQuicktellerBillers()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		HashMap<String, String> extraHeaders = new HashMap<String, String>();
		extraHeaders.put(Interswitch.TERMINAL_ID, "3IWP0001");
		String httpMethod = ConstantUtils.GET;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.QT_BASE_URL +"billers";
		interswitchResponse = interswitch.send(resourceUrl, httpMethod, null,extraHeaders);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> getQuicktellerBillersCategorys()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		HashMap<String, String> extraHeaders = new HashMap<String, String>();
		extraHeaders.put(Interswitch.TERMINAL_ID, "3IWP0001");
		String httpMethod = ConstantUtils.GET;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.QT_BASE_URL +"categorys";
		interswitchResponse = interswitch.send(resourceUrl, httpMethod, null,extraHeaders);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> doTransactionInquiry()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		HashMap<String, String> extraHeaders = new HashMap<String, String>();
		extraHeaders.put(Interswitch.TERMINAL_ID, "3IWP0001");
		String httpMethod = ConstantUtils.POST;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.QT_BASE_URL +"transactions/inquirys";
		
		JSONObject json = new JSONObject();
		json.put("requestReference", "0040556842");
		json.put("customerId", "0040556842");
		json.put("paymentCode", "70001");
		String jsonData = json.toString();
		
		interswitchResponse = interswitch.send(resourceUrl, httpMethod, jsonData,extraHeaders);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> sendTransaction()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		HashMap<String, String> extraHeaders = new HashMap<String, String>();
		extraHeaders.put(Interswitch.TERMINAL_ID, "3IWP0001");
		String httpMethod = ConstantUtils.POST;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.QT_BASE_URL +"transactions";
		
		String pan = "6280511000000095";
		String expDate = "5004";
		String cvv2 = "111";
		String pin = "1111";
		
		HashMap<String, String> secureParameters = interswitch.getSecureData(publicCertPath, pan, expDate, cvv2, pin);
		String pinData = secureParameters.get(ConstantUtils.PINBLOCK);
		String secureData = secureParameters.get(ConstantUtils.SECURE);
		
		double amount = 100;
		String bankCbnCode = "058";
		String msisdn = "07032479501";
		String transactionRef = "IWP|T|Web|3IWP0001|QTFT|261016185145|00000041";
		
		
		JSONObject json = new JSONObject();
		json.put("amount", amount);
		json.put("bankCbnCode", bankCbnCode);
		json.put("msisdn", msisdn);
		json.put("transactionRef", transactionRef);
		json.put("secureData", secureData);
		json.put("pinData", pinData);
		String jsonData = json.toString();
		
		interswitchResponse = interswitch.send(resourceUrl, httpMethod, jsonData,extraHeaders);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> doPayment()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		
		String httpMethod = ConstantUtils.POST;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.PAYMENT_BASE_URL;
		
		String pan = "6280511000000095";
		String expDate = "5004";
		String cvv2 = "111";
		String pin = "1111";
		
		String authData = interswitchPayment.getAuthData(publicCertPath, pan, expDate, cvv2, pin);
		
		double amount = 100;
		String customerId = "1407002510";
		String currency = "NGN";
		String transactionRef = "IWP|T|Web|3IWP0001|QTFT|261016185145|00000041";
		
		
		JSONObject json = new JSONObject();
		json.put("amount", amount);
		json.put("customerId", customerId);
		json.put("currency", currency);
		json.put("transactionRef", transactionRef);
		json.put("authData", authData);
		String jsonData = json.toString();
		
		interswitchResponse = interswitchPayment.send(resourceUrl, httpMethod, jsonData);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> getPaymentStatus()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		HashMap<String, String> extraHeaders = new HashMap<String, String>();
		extraHeaders.put("amount", "100");
		extraHeaders.put("transactionRef", "IWP|T|Web|3IWP0001|QTFT|261016185145|00000041");
		String httpMethod = ConstantUtils.GET;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.PAYMENT_BASE_URL;
		interswitchResponse = interswitchPayment.send(resourceUrl, httpMethod, null,extraHeaders);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> getPaymentInstrumentEwallet()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		String httpMethod = ConstantUtils.GET;
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.EWALLET_BASE_URL+"instruments";
//		get access Token for URL redirect
		String accessToken = "eyJhbGciOiJSUzI1NiJ9.eyJsYXN0TmFtZSI6InRlc3RlciIsIm1lcmNoYW50X2NvZGUiOiJNWDE4NyIsInByb2R1Y3Rpb25fcGF5bWVudF9jb2RlIjoiMDQyNTk0MTMwMjQ2IiwidXNlcl9uYW1lIjoiaXN3dGVzdGVyMkB5YWhvby5jb20iLCJyZXF1ZXN0b3JfaWQiOiIwMDExNzYxNDk5MiIsIm1vYmlsZU5vIjoiMjM0ODA1NjczMTU3NiIsInBheWFibGVfaWQiOiIyMzI0IiwiY2xpZW50X2lkIjoiSUtJQTk2MTRCODIwNjRENjMyRTlCNjQxOERGMzU4QTZBNEFFQTg0RDcyMTgiLCJmaXJzdE5hbWUiOiJ0ZXN0ZXJzIiwiZW1haWxWZXJpZmllZCI6dHJ1ZSwiYXVkIjpbImlzdy1jb2xsZWN0aW9ucyIsImlzdy1wYXltZW50Z2F0ZXdheSIsInBhc3Nwb3J0IiwidmF1bHQiXSwic2NvcGUiOlsicHJvZmlsZSJdLCJleHAiOjE0Nzc1NTIwODQsIm1vYmlsZU5vVmVyaWZpZWQiOnRydWUsImp0aSI6Ijg4OWJiMzQ2LTMwMzMtNDRkNS04MWY1LTUyZDM0ODk4MmM0NSIsImVtYWlsIjoiaXN3dGVzdGVyMkB5YWhvby5jb20iLCJwYXNzcG9ydElkIjoiZTI1MWYwZTktN2JjZi00Y2FlLThlOGItNTZkZjI1ZWQ4NWQwIiwicGF5bWVudF9jb2RlIjoiMDUxNDE5ODE1NDY4NSJ9.fqbIdX2Pyr1xkAkr3FRetA4pSdKGeZRoFeFBD2wtJXosMO4d2er1_YwuVLLcvlAS12LshLPwdPnPaDMN2uhEG-HzY38o4lPE64hUGJmNg_zUjZpfVg5bu--WxqSAKy64IDtVAhh9OwMkn10ZbuTSX0oOFOHwwlVYKs8jdDOUNVvAdAXlgP7_M28i-4HaOHxL-l_Ip_dBOML7BW7cQpLqbyVUmAF-Q0KQXi7XBR2KnSuiYENNGlN5hAJWTpsyt1pcQwTiZF3T5JpaiJC3R7jQlHrb8zTDqFgOS9I0T4wcbPyWn1XfBPkCORVpgygiDVIalC5zp0sZd73OEz9LYHzqGw";
		interswitchResponse = interswitchPayment.sendWithAccessToken(resourceUrl, httpMethod, null,accessToken);
		return interswitchResponse;
	}
	
	/**
	 * @return HashMap<String, String> interswitchResponse
	 * @throws Exception
	 */
	public static HashMap<String, String> generatePaycode()throws Exception 
	{
		HashMap<String, String> interswitchResponse;
		HashMap<String, String> extraHeaders = new HashMap<String, String>();
		extraHeaders.put("frontEndPartnerId", "455");
		//get access Token for URL redirect
		extraHeaders.put("ACCESS_TOKEN", "eyJhbGciOiJSUzI1NiJ9.eyJsYXN0TmFtZSI6InRlc3RlciIsIm1lcmNoYW50X2NvZGUiOiJNWDE4NyIsInByb2R1Y3Rpb25fcGF5bWVudF9jb2RlIjoiMDQyNTk0MTMwMjQ2IiwidXNlcl9uYW1lIjoiaXN3dGVzdGVyMkB5YWhvby5jb20iLCJyZXF1ZXN0b3JfaWQiOiIwMDExNzYxNDk5MiIsIm1vYmlsZU5vIjoiMjM0ODA1NjczMTU3NiIsInBheWFibGVfaWQiOiIyMzI0IiwiY2xpZW50X2lkIjoiSUtJQTk2MTRCODIwNjRENjMyRTlCNjQxOERGMzU4QTZBNEFFQTg0RDcyMTgiLCJmaXJzdE5hbWUiOiJ0ZXN0ZXJzIiwiZW1haWxWZXJpZmllZCI6dHJ1ZSwiYXVkIjpbImlzdy1jb2xsZWN0aW9ucyIsImlzdy1wYXltZW50Z2F0ZXdheSIsInBhc3Nwb3J0IiwidmF1bHQiXSwic2NvcGUiOlsicHJvZmlsZSJdLCJleHAiOjE0Nzc1NTI5MzUsIm1vYmlsZU5vVmVyaWZpZWQiOnRydWUsImp0aSI6IjkwNDU4Njk0LWMyMjctNDM5Mi1iMmNlLTY5YmY5YTE3MmMxMyIsImVtYWlsIjoiaXN3dGVzdGVyMkB5YWhvby5jb20iLCJwYXNzcG9ydElkIjoiZTI1MWYwZTktN2JjZi00Y2FlLThlOGItNTZkZjI1ZWQ4NWQwIiwicGF5bWVudF9jb2RlIjoiMDUxNDE5ODE1NDY4NSJ9.g8f1uoPxiEH8Ftjt4A796_CvL1x5jmjzgq5uNU65ZNMAOk81Q9IUnA2Q5ND9d9MVVSp60xi18useDRZSlnl3BgD-Ol2oPfY0fQWL65MkqmePPfNleEzQPDEaoD3tzOYZZj-y-aNsN1dPv4hlt7W6tOSGvxFbhbKDz4SL2rtyo5eija8mrtZLeFbRz_hPJCoNpF0iOJkJIaebPdoId-tWQJ1Lg9n8Qn5bsNHBJNmjiX2TRFnPqfKlfEYHFRgWzxLaB3oJs66C2xFgjWIOqzWmISD7q_QAt7uFPZZLb4xoar8IyTDlDeJ46U_bQao1UkOVxYtvxEs_6XBSmihA84Oq-Q");
		String httpMethod = ConstantUtils.POST;
		
		String pan = "6280511000000095";
		String expDate = "5004";
		String cvv2 = "111";
		String pin = "1111";
		
		HashMap<String, String> secureParameters = interswitch.getSecureData(publicCertPath, pan, expDate, cvv2, pin);
		String pinData = secureParameters.get(ConstantUtils.PINBLOCK);
		String secureData = secureParameters.get(ConstantUtils.SECURE);
		
		double amount = 100;
		String ttid = "812";
		String msisdn = "07032479501";
		String paymentMethodIdentifier = "48FF5C7F6A3B4C4C961AF6E683D95909";
		String payWithMobileChannel = "ATM";
		String tokenLifeTimeInMinutes = "90";
		String oneTimePin = "1234";
		String macData = "";
		
		String resourceUrl = ConstantUtils.BASE_URL+ConstantUtils.PWM_BASE_URL +msisdn+"/tokens";
		
		JSONObject json = new JSONObject();
		json.put("amount", amount);
		json.put("ttid", ttid);
		json.put("paymentMethodIdentifier", paymentMethodIdentifier);
		json.put("payWithMobileChannel", payWithMobileChannel);
		json.put("tokenLifeTimeInMinutes", tokenLifeTimeInMinutes);
		json.put("oneTimePin", oneTimePin);
		json.put("macData", macData);
		json.put("pinData", pinData);
		json.put("secureData", secureData);
		String jsonData = json.toString();
		
		interswitchResponse = interswitch.send(resourceUrl, httpMethod, jsonData,extraHeaders);
		return interswitchResponse;
	}

}
