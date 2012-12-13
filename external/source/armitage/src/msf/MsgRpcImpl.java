package msf;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;
import org.msgpack.*;
import org.msgpack.object.*;

/**
 * Taken from BSD licensed msfgui by scriptjunkie.
 *
 * Implements an RPC backend using the MessagePack interface
 * @author scriptjunkie
 */
public class MsgRpcImpl extends RpcConnectionImpl {
	private URL u;
	private URLConnection huc; // new for each call
	protected int timeout = 0; /* scriptjunkie likes timeouts, I don't. :) */

	/**
	 * Creates a new URL to use as the basis of a connection.
	 */
	public MsgRpcImpl(String username, String password, String host, int port, boolean ssl, boolean debugf) throws MalformedURLException {
		if (ssl) { // Install the all-trusting trust manager & HostnameVerifier
			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, new TrustManager[] {
					new X509TrustManager() {
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}
						public void checkClientTrusted(
							java.security.cert.X509Certificate[] certs, String authType) {
						}
						public void checkServerTrusted(
							java.security.cert.X509Certificate[] certs, String authType) {
						}
					}
				}, new java.security.SecureRandom());

				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier( new HostnameVerifier() {
					public boolean verify(String string,SSLSession ssls) {
						return true;
					}
				});
			}
			catch (Exception e) {
			}
			u = new URL("https", host, port, "/api/1.0/");
		}
		else {
			u = new URL("http", host, port, "/api/1.0/");
		}

		/* login to msf server */
		Object[] params = new Object[]{ username, password };
		Map results = exec("auth.login",params);

		/* save the temp token (lasts for 5 minutes of inactivity) */
		rpcToken = results.get("token").toString();

		/* generate a non-expiring token and use that */
		params = new Object[]{ rpcToken };
		results = exec("auth.token_generate", params);
		rpcToken = results.get("token").toString();
	}

	/**
	 * Decodes a response recursively from MessagePackObject to a normal Java object
	 * @param src MessagePack response
	 * @return decoded object
	 */
	private static Object unMsg(Object src){
		Object out = src;
		if (src instanceof ArrayType) {
			List l = ((ArrayType)src).asList();
			List outList = new ArrayList(l.size());
			out = outList;
			for(Object o : l)
				outList.add(unMsg(o));
		}
		else if (src instanceof BooleanType) {
			out = ((BooleanType)src).asBoolean();
		}
		else if (src instanceof FloatType) {
			out = ((FloatType)src).asFloat();
		}
		else if (src instanceof IntegerType) {
			out = ((IntegerType)src).asInt();
		}
		else if (src instanceof MapType) {
			Set ents = ((MapType)src).asMap().entrySet();
			out = new HashMap();
			for (Object ento : ents) {
				Map.Entry ent = (Map.Entry)ento;
				Object key = unMsg(ent.getKey());
				Object val = ent.getValue();
				// Hack - keep bytes of generated or encoded payload
				if(ents.size() == 1 && val instanceof RawType && (key.equals("payload") || key.equals("encoded")))
					val = ((RawType)val).asByteArray();
				else
					val = unMsg(val);
				((Map)out).put(key + "", val);
			}

			if (((Map)out).containsKey("error") && ((Map)out).containsKey("error_class")) {
				System.out.println(((Map)out).get("error_backtrace"));
				throw new RuntimeException(((Map)out).get("error_message").toString());
			}
		}
		else if (src instanceof NilType) {
			out = null;
		}
		else if (src instanceof RawType) {
			out = ((RawType)src).asString();
		}
		return out;
	}

	/** Creates an XMLRPC call from the given method name and parameters and sends it */
	protected void writeCall(String methodName, Object[] args) throws Exception {
		huc = u.openConnection();
		huc.setDoOutput(true);
		huc.setDoInput(true);
		huc.setUseCaches(false);
		huc.setRequestProperty("Content-Type", "binary/message-pack");
		huc.setReadTimeout(0);
		OutputStream os = huc.getOutputStream();
		Packer pk = new Packer(os);

		pk.packArray(args.length+1);
		pk.pack(methodName);
		for(Object o : args)
			pk.pack(o);
		os.close();
	}

	/** Receives an RPC response and converts to an object */
	protected Object readResp() throws Exception {
		InputStream is = huc.getInputStream();
		MessagePackObject mpo = MessagePack.unpack(is);
		return unMsg(mpo);
	}
}
