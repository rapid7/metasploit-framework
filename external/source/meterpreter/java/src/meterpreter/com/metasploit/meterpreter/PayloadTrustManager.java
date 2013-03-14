package com.metasploit.meterpreter;

import java.net.URLConnection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * Trust manager used for HTTPS URL connection. This is in its own class because it
 * depends on classes only present on Sun JRE 1.4+, and incorporating it into
 * the main {@link Meterpreter} class would have made it impossible for other/older
 * JREs to load it.
 * 
 * This class is substantically identical to the metasploit.PayloadTrustManager class,
 * only that it tries to cache the ssl context and trust manager between calls.
 */
public class PayloadTrustManager implements X509TrustManager, HostnameVerifier {

	public X509Certificate[] getAcceptedIssuers() {
		// no preferred issuers
		return new X509Certificate[0];
	}

	public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
		// trust everyone
	}

	public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
		// trust everyone
	}
	
	public boolean verify(String hostname, SSLSession session) {
		// trust everyone
		return true;
	}

	private static PayloadTrustManager instance;
	private static SSLSocketFactory factory;
	
	/**
	 * Called by the {@link Payload} class to modify the given
	 * {@link URLConnection} so that it uses this trust manager.
	 */
	public static synchronized void useFor(URLConnection uc) throws Exception {
		if (uc instanceof HttpsURLConnection) {
			HttpsURLConnection huc = ((HttpsURLConnection) uc);
			if (instance == null) {
				instance = new PayloadTrustManager();
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, new TrustManager[] { instance }, new java.security.SecureRandom());
				factory = sc.getSocketFactory();
			}
			huc.setSSLSocketFactory(factory);
			huc.setHostnameVerifier(instance);
		}
	}
}
