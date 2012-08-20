package ssl;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import javax.net.*;

import java.security.*;
import java.security.cert.*;

import sleep.bridges.io.*;

/* taken from jIRCii, I developed it, so I get to do what I want ;) */
public class SecureSocket {
	protected SSLSocket socket;

	public SecureSocket(String host, int port, ArmitageTrustListener checker) throws Exception {
		socket = null;

		SSLContext sslcontext = SSLContext.getInstance("SSL");
		sslcontext.init(null, new TrustManager[] { new ArmitageTrustManager(checker) }, new java.security.SecureRandom());
		SSLSocketFactory factory = (SSLSocketFactory) sslcontext.getSocketFactory();

		socket = (SSLSocket)factory.createSocket(host, port);

		socket.setSoTimeout(4048);
		socket.startHandshake();
	}

	public IOObject client() {
		try {
			IOObject temp = new IOObject();
			temp.openRead(socket.getInputStream());
			temp.openWrite(new BufferedOutputStream(socket.getOutputStream(), 8192 * 8));
			socket.setSoTimeout(0);
			return temp;
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public Socket getSocket() {
		return socket;
	}
}

