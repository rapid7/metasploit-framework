package msfgui;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.jdesktop.application.Task;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * RpcConnection handles connection details to a msfrpcd and automatically sends 
 * activity to be logged. It also caches some method calls to more quickly
 * retrieve results later.
 * 
 * Implements a minimal XMLRPC client for our purposes. Reinventing the wheel is 
 * usually a bad idea, but CVE/description searching takes a long time and this
 * implementation runs a CVE search twice as fast as the apache libs. It also
 * results in a more responsive console.
 * 
 * @author scriptjunkie
 */
public class RpcConnection {
	private String rpcToken;
	private Map callCache = new HashMap();
	public static String defaultUser = "msf",defaultPass = null, defaultHost = "127.0.0.1";
	public static int defaultPort = 55553;
	public static boolean defaultSsl = false;
	public static boolean disableDb = false;
	private Socket connection;
	private OutputStream sout; //socket output/input
	private InputStream sin;
	private final Object lockObject = new Object();//to synchronize one request at a time
	private String username, password, host;
	private int port;
	private boolean ssl;

	/** Constructor sets up a connection and authenticates. */
	RpcConnection(String username, char[] password, String host, int port, boolean ssl) throws MsfException {
		boolean haveRpcd=false;
		this.username = username;
		this.password = new String(password);
		this.host = host;
		this.port = port;
		this.ssl = ssl;
		String message = "";
		try {
			connect();
			Map results = exec("auth.login",new Object[]{username, this.password});
			rpcToken=results.get("token").toString();
			haveRpcd=results.get("result").equals("success");
		} catch (MsfException xre) {
			message = xre.getLocalizedMessage();
		} catch (IOException io){
			message = io.getLocalizedMessage();
		} catch (NullPointerException nex){
		} catch (NoSuchAlgorithmException nsax){
		} catch (KeyManagementException kmx){
		}
		if(!haveRpcd)
			throw new MsfException("Error connecting. "+message);
		Map root = MsfguiApp.getPropertiesNode();
		root.put("username", username);
		root.put("password", this.password);
		root.put("host", host);
		root.put("port", port);
		root.put("ssl", ssl);
		root.put("disableDb", disableDb);
		MsfguiApp.savePreferences();
	}

	/**
	 * Disconnects then reconnects.
	 *
	 * @throws SocketException
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	private void reconnect() throws SocketException, KeyManagementException, IOException, NoSuchAlgorithmException {
		connection.close();
		connect();
	}

	/**
	 * Connects the TCP stream, setting up SSL if necessary.
	 *
	 * @throws SocketException
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	private void connect() throws SocketException, KeyManagementException, IOException, NoSuchAlgorithmException {
		if (ssl) {
			TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
				}
				public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
				}
			}};
			// Let us create the factory where we can set some parameters for the connection
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			connection = sc.getSocketFactory().createSocket(host, port);
		} else {
			connection = new Socket(host, port);
		}
		connection.setSoTimeout(10000); //Ten second timeout
		sout = connection.getOutputStream();
		sin = connection.getInputStream();
	}

	public String toString(){
		return "RPC connection "
				+ "\nusername: "+username
				+ "\npassword: " + password
				+ "\nhost: " + host
				+ "\nport: " + Integer.toString(port)
				+ "\nssl: " + ssl;
	}
	/** Destructor cleans up. */
	protected void finalize() throws Throwable{
		super.finalize();
		connection.close();
	}

	/** Adds token, runs command, and notifies logger on call and return */
	public Object execute(String methodName, Object... params) throws MsfException{
		MsfguiLog.defaultLog.logMethodCall(methodName, params);
		Object[] paramsNew = new Object[params.length+1];
		paramsNew[0] = rpcToken;
		System.arraycopy(params, 0, paramsNew, 1, params.length);
		Object result = cacheExecute(methodName, paramsNew);
		MsfguiLog.defaultLog.logMethodReturn(methodName, params, result);
		return result;
	}

	/** Caches certain calls and checks cache for re-executing them.
	 * If not cached or not cacheable, calls exec. */
	private Object cacheExecute(String methodName, Object[] params) throws MsfException{
		if(methodName.equals("module.info") || methodName.equals("module.options")
				|| methodName.equals("module.compatible_payloads") || methodName.equals("module.post")){
			StringBuilder keysb = new StringBuilder(methodName);
			for(int i = 1; i < params.length; i++)
				keysb.append(params[i].toString());
			String key = keysb.toString();
			Object result = callCache.get(key);
			if(result == null){
				result = exec(methodName, params);
				callCache.put(key, result);
			}
			if(result instanceof Map){
				HashMap clone = new HashMap();
				clone.putAll((Map)result);
				return clone;
			}
			return result;
		}
		return exec(methodName, params);
	}

	/** Method that sends a call to the server and received a response; only allows one at a time */
	private Map exec (String methname, Object[] params) throws MsfException{
		synchronized(lockObject){ //Only one method call at a time!
			try{
				writeCall(methname, params);
				return (Map)readResp();
			}catch(Exception ex){ //any weirdness gets wrapped in a MsfException
				try{
					if(ex instanceof java.net.SocketTimeoutException) 
						reconnect();  //reconnect on socket timeout
				}catch (Exception ex2){
					ex = ex2;
				}
				if(! (ex instanceof MsfException)){
					if(! MsfguiApp.shuttingDown || !ex.getLocalizedMessage().toLowerCase().contains("broken pipe")){
						ex.printStackTrace();
						throw new MsfException("Error in call: "+ex.getLocalizedMessage(), ex);
					}
				}
				throw (MsfException)ex;
			}
		}
	}

	/** Creates an XMLRPC call from the given method name and parameters and sends it */
	protected void writeCall(String methname, Object[] params) throws Exception{
		Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element methodCall = doc.createElement("methodCall");
		doc.appendChild(methodCall);
		Element methodName = doc.createElement("methodName");
		methodName.appendChild(doc.createTextNode(methname));
		methodCall.appendChild(methodName);
		Element paramsEl = doc.createElement("params");
		methodCall.appendChild(paramsEl);
		//Add each parameter by type. Usually just the maps are difficult
		for(Object param : params){
			Element paramEl = doc.createElement("param");
			paramEl.appendChild(objectToNode(doc,param));
			paramsEl.appendChild(paramEl);
		}
		ByteArrayOutputStream bout = new  ByteArrayOutputStream();
		TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(bout));
		sout.write(bout.toByteArray());
		sout.write(0);
	}

	/**
	 * Takes the object provided and recursively creates a node out of it suitable
	 * for xmlrpc transmission.
	 * @param doc
	 * @param param
	 * @return
	 */
	public static Node objectToNode(Document doc, Object param){
		Node valEl = doc.createElement("value");
		if(param instanceof Map){ //Reverse of the parseVal() struct-to-HashMap code
			Element structEl = doc.createElement("struct");
			for(Object entryObj : ((Map)param).entrySet()){
				Map.Entry ent = (Map.Entry)entryObj;
				Element membEl = doc.createElement("member");
				Element nameEl = doc.createElement("name");
				nameEl.appendChild(doc.createTextNode(ent.getKey().toString()));
				membEl.appendChild(nameEl);
				membEl.appendChild(objectToNode(doc,ent.getValue()));
				structEl.appendChild(membEl);
			}
			valEl.appendChild(structEl);
		}else if(param instanceof List || param instanceof Object[]){ //Reverse of the parseVal() array-to-HashMap code
			Element arrayEl = doc.createElement("array");
			Element dataEl = doc.createElement("data");
			if(param instanceof Object[])
				for(Object obj : (Object[])param)
					dataEl.appendChild(objectToNode(doc,obj));
			else
				for(Object obj : (List)param)
					dataEl.appendChild(objectToNode(doc,obj));
			arrayEl.appendChild(dataEl);
			valEl.appendChild(arrayEl);
		}else if(param instanceof Integer){ //not sure I even need this
			Element i4El = doc.createElement("i4");
			i4El.appendChild(doc.createTextNode(param.toString()));
			valEl.appendChild(i4El);
		}else if(param instanceof Boolean){ //not sure I even need this
			Element boolEl = doc.createElement("boolean");
			boolEl.appendChild(doc.createTextNode(param.toString()));
			valEl.appendChild(boolEl);
		}else{
			Element strEl = doc.createElement("string");
			strEl.appendChild(doc.createTextNode(param.toString()));
			valEl.appendChild(strEl);
		}
		return valEl;
	}

	/** Receives an XMLRPC response and converts to an object */
	protected Object readResp() throws Exception{
		//Will store our response
		StringBuilder sb = new StringBuilder();
		int len;
		do{
			//read bytes
			ByteArrayOutputStream cache = new ByteArrayOutputStream();
			int val;
			while((val = sin.read()) != 0){
				if(val == -1)
					throw new MsfException("Stream died.");
				cache.write(val);
			}
			//parse the response: <methodResponse><params><param><value>...
			ByteArrayInputStream is = new ByteArrayInputStream(cache.toByteArray());
			int a = is.read();
			while(a != -1){
				if(!Character.isISOControl(a) || a == '\t')
					sb.append((char)a);
				//else
				//	sb.append("&#x").append(Integer.toHexString(a)).append(';');
				a = is.read();
			}
			len = sb.length();//Check to make sure we aren't stopping on an embedded null
		} while (sb.lastIndexOf("</methodResponse>") < len - 20 || len < 30);
		Document root = DocumentBuilderFactory.newInstance().newDocumentBuilder()
				.parse(new ByteArrayInputStream(sb.toString().getBytes()));
		
		if(!root.getFirstChild().getNodeName().equals("methodResponse"))
			throw new MsfException("Error reading response: not a response.");
		Node methResp = root.getFirstChild();
		if(methResp.getFirstChild().getNodeName().equals("fault")){
			throw new MsfException(methResp.getFirstChild()//fault 
					.getFirstChild() // value
					.getFirstChild() // struct
					.getLastChild() // member
					.getLastChild() // value
					.getTextContent());
		}
		Node params = methResp.getFirstChild();
		if(!params.getNodeName().equals("params"))
			throw new MsfException("Error reading response: no params.");
		Node param = params.getFirstChild();
		if(!param.getNodeName().equals("param"))
			throw new MsfException("Error reading response: no param.");
		Node value = param.getFirstChild();
		if(!value.getNodeName().equals("value"))
			throw new MsfException("Error reading response: no value.");
		return parseVal(value);
	}

	/** Takes an XMLRPC DOM value node and creates a java object out of it recursively */
	public static Object parseVal(Node submemb) throws MsfException {
		Node type = submemb.getFirstChild();
		String typeName = type.getNodeName();
		if(typeName.equals("string")){//<struct><member><name>jobs</name><value><struct/></value></member></struct>
			return type.getTextContent(); //String returns java string
		}else if (typeName.equals("array")){ //Array returns List
			ArrayList arrgh = new ArrayList();
			Node data = type.getFirstChild();
			if(!data.getNodeName().equals("data"))
				throw new MsfException("Error reading array: no data.");
			for(Node val = data.getFirstChild(); val != null; val = val.getNextSibling())
				arrgh.add(parseVal(val));
			return arrgh;
		}else if (typeName.equals("struct")){ //Struct returns a HashMap of name->value member pairs
			HashMap structmembs = new HashMap();
			for(Node member = type.getFirstChild(); member != null; member = member.getNextSibling()){
				if(!member.getNodeName().equals("member"))
					throw new MsfException("Error reading response: non struct member.");
				Object name = null, membValue = null;
				//get each member and put into output map
				for(Node submember = member.getFirstChild(); submember != null; submember = submember.getNextSibling()){
					if(submember.getNodeName().equals("name"))
						name = submember.getTextContent();
					else if (submember.getNodeName().equals("value"))
						membValue = parseVal(submember); //Value can be arbitrarily complex
				}
				structmembs.put(name, membValue);
			}
			return structmembs;
		}else if (typeName.equals("i4")){
			return new Integer(type.getTextContent());
		}else if (typeName.equals("boolean")){
			return type.getTextContent().equals("1") || Boolean.valueOf(type.getTextContent());
		}else if (typeName.equals("dateTime.iso8601")) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd'T'HH:mm:ss");
			try{
				return sdf.parse(type.getTextContent());
			}catch(ParseException pex){
				return type.getTextContent();
			}
		} else {
			throw new MsfException("Error reading val: unknown type " + typeName);
		}
	}

	/** Attempts to start msfrpcd and connect to it.*/
	public static Task startRpcConn(final MainFrame mainFrame){
		if(mainFrame.rpcConn != null){
			MsfguiApp.showMessage(mainFrame.getFrame(), "You are already connected!\n"
					+ "Exit before making a new connection.");
			throw new RuntimeException("Already connected");
		}
		return new Task<RpcConnection, Void>(mainFrame.getApplication()){
			private RpcConnection myRpcConn;
			@Override
			protected RpcConnection doInBackground() throws Exception {
				setTitle("Starting new msfrpcd");
				setMessage("Setting up and saving parameters.");
				if(defaultPass == null){
					StringBuilder password = new StringBuilder();
					Random secrand = new SecureRandom();
					for (int i = 0; i < 10; i++)
						password.append((char) ('a'+secrand.nextInt(26)));
					defaultPass = password.toString();
				}

				// Don't fork cause we'll check if it dies
				java.util.List args = new java.util.ArrayList(java.util.Arrays.asList(new String[]{
						"msfrpcd","-f","-P",defaultPass,"-t","Basic","-U",defaultUser,"-a","127.0.0.1"}));
				if(!defaultSsl)
					args.add("-S");
				if(disableDb)
					args.add("-n");
				setMessage("Starting msfrpcd.");
				Process proc = null;
				try {
					proc = MsfguiApp.startMsfProc(args);
				} catch (MsfException ex) {
					setMessage("msfrpcd not found.");
					setProgress(1f);
					throw new MsfException("Could not find or start msfrpcd"); //darn
				}

				//Connect to started daemon
				setMessage("Started msfrpcd. Connecting to new msfrpcd...");
				boolean connected = false;
				for (int tries = 0; tries < 10000; tries++) { //it usually takes a minute to get started

					try{ //unfortunately this is the only direct way to check if process has terminated
						int exitval = proc.exitValue();
						setMessage("msfrpcd died with exit value "+exitval);
						throw new MsfException("msfrpcd died");
					} catch (IllegalThreadStateException itsy){
					} //Nope. We're good.

					try {
						myRpcConn = new RpcConnection(defaultUser, defaultPass.toCharArray(), "127.0.0.1", defaultPort, defaultSsl);
						connected = true;
						break;
					} catch (MsfException mex) {
						if(mex.getMessage().toLowerCase().contains("authentication error")){
							mex.printStackTrace();
							setMessage("Cannot connect to started msfrpcd.");
							throw mex;
						}else if(mex.getMessage().toLowerCase().contains("connection reset")){
							mex.printStackTrace();
							setMessage("Connection reset.");
							throw mex;
						}else if(mex.getMessage().toLowerCase().contains("timed out")){
							mex.printStackTrace();
							setMessage("Timeout.");
							throw mex;
						}
					}
					try {
						Thread.sleep(200); //Wait for msfrpcd to be ready
					} catch (InterruptedException iex) {
					}
				}//end try to connect loop
				if(!connected){
					setMessage("Cannot connect to started msfrpcd.");
					throw new MsfException("Cannot connect to started msfrpcd.");
				}
				return myRpcConn;
			}
			@Override
			protected void succeeded(RpcConnection myRpcConn) {
				mainFrame.rpcConn = myRpcConn;
				mainFrame.getModules();
			}
		};
	}
}
