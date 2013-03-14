package ssl;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import javax.net.*;
import java.util.*;

import java.security.*;
import java.security.cert.*;

import java.math.*;

import javax.swing.*;

public class ArmitageTrustManager implements X509TrustManager {
	protected ArmitageTrustListener checker;

	public ArmitageTrustManager(ArmitageTrustListener checker) {
		this.checker = checker;
	}

	public void checkClientTrusted(X509Certificate ax509certificate[], String authType) {
		return;
	}

	public void checkServerTrusted(X509Certificate ax509certificate[], String authType) throws CertificateException {
		try {
			for (int x = 0; x < ax509certificate.length; x++) {
				byte[] bytesOfMessage = ax509certificate[x].getEncoded();
				MessageDigest md = MessageDigest.getInstance("SHA1");
				byte[] thedigest = md.digest(bytesOfMessage);

				BigInteger bi = new BigInteger(1, thedigest);
				String fingerprint = bi.toString(16);

				if (checker != null && !checker.trust(fingerprint))
					throw new CertificateException("Certificate Rejected. Press Cancel.");
			}

			return;
		}
		catch (CertificateException cex) {
			throw cex;
		}
		catch (Exception ex) {
			throw new CertificateException(ex.getMessage());
		}
	}

	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}
}
