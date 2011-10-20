package msfgui;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.msgpack.MessagePack;
import org.msgpack.MessagePackObject;
import org.msgpack.Packer;
import org.msgpack.object.*;

/**
 * Implements an RPC backend using the MessagePack interface
 * @author scriptjunkie
 */
public class MsgRpc extends RpcConnection {
	private URL u;
	private URLConnection huc; // new for each call
	protected int timeout = 5000;

	/**
	 * Creates a new URL to use as the basis of a connection.
	 */
	protected void connect() throws MalformedURLException{
		if(ssl){ // Install the all-trusting trust manager & HostnameVerifier
			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, new TrustManager[]{
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
				HttpsURLConnection.setDefaultHostnameVerifier( new HostnameVerifier(){
					public boolean verify(String string,SSLSession ssls) {
						return true;
					}
				});
			} catch (Exception e) {
			}
			u = new URL("https",host,port,"/api/1.0");
		}else{
			u = new URL("http",host,port,"/api/1.0");
		}
	}

	/**
	 * Decodes a response recursively from MessagePackObject to a normal Java object
	 * @param src MessagePack response
	 * @return decoded object
	 */
	private static Object unMsg(Object src){
		Object out = src;
		if(src instanceof ArrayType){
			List l = ((ArrayType)src).asList();
			List outList = new ArrayList(l.size());
			out = outList;
			for(Object o : l)
				outList.add(unMsg(o));
		}else if(src instanceof BooleanType){
			out = ((BooleanType)src).asBoolean();
		}else if(src instanceof FloatType){
			out = ((FloatType)src).asFloat();
		}else if(src instanceof IntegerType){
			out = ((IntegerType)src).asInt();
		}else if(src instanceof MapType){
			Set ents = ((MapType)src).asMap().entrySet();
			out = new HashMap();
			for (Object ento : ents){
				Map.Entry ent = (Map.Entry)ento;
				Object key = unMsg(ent.getKey());
				Object val = ent.getValue();
				// Hack - keep bytes of generated or encoded payload
				if(ents.size() == 1 && val instanceof RawType &&
						(key.equals("payload") || key.equals("encoded")))
					val = ((RawType)val).asByteArray();
				else
					val = unMsg(val);
				((Map)out).put(key, val);
			}
			if(((Map)out).containsKey("error") && ((Map)out).containsKey("error_class")){
				System.out.println(((Map)out).get("error_backtrace"));
				throw new MsfException(((Map)out).get("error_message").toString());
			}
		}else if(src instanceof NilType){
			out = null;
		}else if(src instanceof RawType){
			out = ((RawType)src).asString();
		}
		return out;
	}

	/** Creates an XMLRPC call from the given method name and parameters and sends it */
	protected void writeCall(String methodName, Object[] args) throws Exception{
		huc = u.openConnection();
		huc.setDoOutput(true);
		huc.setDoInput(true);
		huc.setUseCaches(false);
		huc.setRequestProperty("Content-Type", "binary/message-pack");
		huc.setReadTimeout(timeout);
		OutputStream os = huc.getOutputStream();
		Packer pk = new Packer(os);

		pk.packArray(args.length+1);
		pk.pack(methodName);
		for(Object o : args)
			pk.pack(o);
		os.close();
	}

	/** Receives an RPC response and converts to an object */
	protected Object readResp() throws Exception{
		InputStream is = huc.getInputStream();
		MessagePackObject mpo = MessagePack.unpack(is);
		return unMsg(mpo);
	}
}
