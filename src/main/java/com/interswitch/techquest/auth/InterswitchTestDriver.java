package com.interswitch.techquest.auth;

import java.util.HashMap;

import org.json.JSONObject;

import com.interswitch.techquest.auth.utils.ConstantUtils;

public class InterswitchTestDriver {

	static Interswitch interswitch = new Interswitch("IKIAF6C068791F465D2A2AA1A3FE88343B9951BAC9C3", "FTbMeBD7MtkGBQJw1XoM74NaikuPL13Sxko1zb0DMjI=",Interswitch.ENV_SANDBOX);
	static Interswitch interswitchPayment = new Interswitch("IKIA9614B82064D632E9B6418DF358A6A4AEA84D7218", "XCTiBtLy1G9chAnyg0z3BcaFK4cVpwDg/GTw2EmjTZ8=",Interswitch.ENV_SANDBOX);
	static Interswitch interswitchPwm = new Interswitch("IKIAD8CEC8152D8E720E2CC7961C8EBBCD391A0DA0B6", "79EsDAYDw1mPiLre/z5RiqfH0XgMd8n2uKkThJ9YyA4=",Interswitch.ENV_SANDBOX);
	static String publicCertPath = "../interswitch-java/src/main/resources/paymentgateway.crt";
	public static void main(String[] args) throws Exception 
	{
		HashMap<String, String> interswitchResponse = new HashMap<String, String>();
		
//		interswitchResponse = getPaymentInstrument();
		interswitchResponse = getQuicktellerBillers();
//		interswitchResponse = getQuicktellerBillersCategorys();
//		interswitchResponse = doTransactionInquiry();
//		interswitchResponse = sendTransaction();
//		interswitchResponse = doPayment();
//		interswitchResponse = getPaymentStatus();
//		interswitchResponse = getPaymentInstrumentEwallet();
//		interswitchResponse = generatePaycode();
		
		
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
		String phoneNumber = "2348056731576";
		String scheme = ConstantUtils.SCHEME;
		String merchantid = ConstantUtils.MERCHANT_ID;
		String channel = ConstantUtils.CHANNEL;
		String version = ConstantUtils.VERSION;
		String transactionType = "getallpaymentmethods";
		String httpMethod = ConstantUtils.GET;
		String resourceUrl = ConstantUtils.VERVE_BASE_URL + phoneNumber+ "/paymentmethods.json?scheme=" + scheme + "&channel="
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
		String resourceUrl = ConstantUtils.QT_BASE_URL +"billers";
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
		String resourceUrl = ConstantUtils.QT_BASE_URL +"categorys";
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
		String resourceUrl = ConstantUtils.QT_BASE_URL +"transactions/inquirys";
		
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
		String resourceUrl = ConstantUtils.QT_BASE_URL +"transactions";
		
		String pan = "6280511000000095";
//		pan = "5060990580000217499";
		String expDate = "5004";
		String cvv2 = "111";
		String pin = "1111";
		int macVer = 11;
		
		HashMap<String, String> secureParameters = interswitch.getSecureData(pan, expDate, cvv2, pin,publicCertPath, macVer);
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
		String resourceUrl = ConstantUtils.PAYMENT_BASE_URL;
		
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
		String resourceUrl = ConstantUtils.PAYMENT_BASE_URL;
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
		String resourceUrl = ConstantUtils.EWALLET_BASE_URL+"instruments";
//		get access Token for URL redirect
		String accessToken = "eyJhbGciOiJSUzI1NiJ9.eyJsYXN0TmFtZSI6ImVyaG9iYWdhLWFnb2Z1cmUiLCJtZXJjaGFudF9jb2RlIjoiTVgxODciLCJwcm9kdWN0aW9uX3BheW1lbnRfY29kZSI6IjA0MjU5NDEzMDI0NiIsInVzZXJfbmFtZSI6ImVyaG9iYWdhZXZhbnNAeWFob28uY29tIiwicmVxdWVzdG9yX2lkIjoiMDAxMTc2MTQ5OTIiLCJtb2JpbGVObyI6IjIzNDgwOTA2NzM1MjAiLCJwYXlhYmxlX2lkIjoiMjMyNCIsImNsaWVudF9pZCI6IklLSUE5NjE0QjgyMDY0RDYzMkU5QjY0MThERjM1OEE2QTRBRUE4NEQ3MjE4IiwiZmlyc3ROYW1lIjoiZXZhbnMiLCJlbWFpbFZlcmlmaWVkIjp0cnVlLCJhdWQiOlsiaXN3LWNvbGxlY3Rpb25zIiwiaXN3LXBheW1lbnRnYXRld2F5IiwicGFzc3BvcnQiLCJ2YXVsdCJdLCJzY29wZSI6WyJwcm9maWxlIl0sImV4cCI6MTQ3NzYwODU4OSwibW9iaWxlTm9WZXJpZmllZCI6dHJ1ZSwianRpIjoiMWUyNTQ0ZjAtMzZhZi00NzdjLWE0ZjItNTc2ODk1YTJjMjE0IiwiZW1haWwiOiJlcmhvYmFnYWV2YW5zQHlhaG9vLmNvbSIsInBhc3Nwb3J0SWQiOiI5YjYwY2NmMS1mYjA2LTRkZGQtODExZC00NDkxNDlkN2E5NjkiLCJwYXltZW50X2NvZGUiOiIwNTE0MTk4MTU0Njg1In0.RyXef2i9H5i9s3jInbviFqkazKnOhknrWe6gXvyqKGWOPdvKNt_AE4fjM4AoJCgq24cqIEfAXyIUKs6ysFxnOa7SbxQ5SOoSX2b_IxADoxAVYkSvomJ_Q6i6FSyQG3vszHrM4iza_oQXxSWjVXHtOsS3MNWYS7zDisfmqdlYrc1JfrK1zhnSvKPlNMyoCt1Wv2kTymTnS8TmYt2j84A-DUMpU8DU03obu66cxGXFRwncjWLz53LkEAaLJ9Of0bz98yriK6NB3MO-bhS12oBNxGaT1EB85keV_SUQh9dAaYZY6X0XdhZ4FiaL83IJHU_EHiXDTuUU992Qvnr8Ja7l3Q";
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
//		extraHeaders.put("ACCESS_TOKEN", "eyJhbGciOiJSUzI1NiJ9.eyJsYXN0TmFtZSI6IkpBTSIsIm1lcmNoYW50X2NvZGUiOiJNWDE4NyIsInByb2R1Y3Rpb25fcGF5bWVudF9jb2RlIjoiMDQyNTk0MTMwMjQ2IiwidXNlcl9uYW1lIjoiYXBpLWphbUBpbnRlcnN3aXRjaGdyb3VwLmNvbSIsInJlcXVlc3Rvcl9pZCI6IjAwMTE3NjE0OTkyIiwibW9iaWxlTm8iOiIyMzQ4MDk4Njc0NTIzIiwicGF5YWJsZV9pZCI6IjIzMjQiLCJjbGllbnRfaWQiOiJJS0lBOTYxNEI4MjA2NEQ2MzJFOUI2NDE4REYzNThBNkE0QUVBODRENzIxOCIsImZpcnN0TmFtZSI6IkFQSSIsImVtYWlsVmVyaWZpZWQiOnRydWUsImF1ZCI6WyJpc3ctY29sbGVjdGlvbnMiLCJpc3ctcGF5bWVudGdhdGV3YXkiLCJwYXNzcG9ydCIsInZhdWx0Il0sInNjb3BlIjpbInByb2ZpbGUiXSwiZXhwIjoxNDc3NTk5MDMwLCJtb2JpbGVOb1ZlcmlmaWVkIjp0cnVlLCJqdGkiOiI4ZWNhNjY4My1mZGE0LTQ2MzgtYjllNi0xOWE2MDg2M2JiYzYiLCJlbWFpbCI6ImFwaS1qYW1AaW50ZXJzd2l0Y2hncm91cC5jb20iLCJwYXNzcG9ydElkIjoiNjExZGY3NmEtYjQzMi00NzM3LTljNjQtNzYwN2RhZGNhY2FkIiwicGF5bWVudF9jb2RlIjoiMDUxNDE5ODE1NDY4NSJ9.ObqEaUR9NwF7PXI7RnM8-4R9FBVTHa-2VUiFHXBJAPQwck5qNHNupxfK1FB6o6C4YmXBsCxlNpk9QklUk-6eDasyRKjqHrBSiam7qZoim2TIiH_UCEdlV917U8iilO5uVuaeI-ISclI7qiHO9JRBwoUWBFVkPPrZkB-OarK0lcHlJ_F23rrE0LerQeMktG9GURYpi-uEaTzJ83qhm6OghHMbq5D7ax3_bHEwui0ri7ez8mbA1jObsDcYMKKUZprSTaFUprIHP3i9OVVK6dAYrnjWhTH0PL0lPATLMrmCs_Xy9cH5lXf_sKO-dQPi61zLLygMBGqDIcL4CSPPCUOV5g");
		String httpMethod = ConstantUtils.POST;
		
		String pan = "";//"0000000000000000";
		String expDate = "";
		String cvv2 = "";
		String pin = "1111";
		
		double amount = 100000;
		String ttid = "812";
		String msisdn = "2348090673520";
		String paymentMethodIdentifier = "FEED1FCDDBD14AA1822FD1B9254B4C43";
		String payWithMobileChannel = "ATM";
		String tokenLifeTimeInMinutes = "90";
		String oneTimePin = "1234";
		
		HashMap<String,String> additionalSecureData = new HashMap<String, String>();
		additionalSecureData.put("msisdn",msisdn);
		additionalSecureData.put("ttid", ttid);
		additionalSecureData.put("cardName", "default");
		int macVer = 11;
		
		
		HashMap<String, String> secureParameters = interswitchPwm.getSecureData(pan, expDate, cvv2, pin,additionalSecureData,publicCertPath, macVer);
		String pinData = secureParameters.get(ConstantUtils.PINBLOCK);
		String secureData = secureParameters.get(ConstantUtils.SECURE);
		
		String resourceUrl = ConstantUtils.PWM_BASE_URL +msisdn+"/tokens";
		
		JSONObject json = new JSONObject();
		json.put("amount", amount);
		json.put("ttid", ttid);
		json.put("paymentMethodIdentifier", paymentMethodIdentifier);
		json.put("payWithMobileChannel", payWithMobileChannel);
		json.put("tokenLifeTimeInMinutes", tokenLifeTimeInMinutes);
		json.put("oneTimePin", oneTimePin);
		json.put("pinData", pinData);
		json.put("secure", secureData);
		String jsonData = json.toString();
		
		interswitchResponse = interswitchPwm.send(resourceUrl, httpMethod, jsonData,extraHeaders);
		return interswitchResponse;
	}

}
