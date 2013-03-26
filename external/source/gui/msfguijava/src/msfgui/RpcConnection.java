package msfgui;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.jdesktop.application.Task;

/**
 * RpcConnection handles connection details to a msfrpcd and automatically sends 
 * activity to be logged. It also caches some method calls to more quickly
 * retrieve results later.
 *
 * Connection implementation is left to child classes, which must implemtent
 * writeCall() and readResp() and may implement connect.
 * 
 * @author scriptjunkie
 */
public abstract class RpcConnection {
	protected String rpcToken;
	protected Map callCache = new HashMap();
	public static String defaultUser = "msf",defaultPass = null, defaultHost = "127.0.0.1";
	public static int defaultPort = 55553;
	public static boolean defaultSsl = false;
	public static boolean disableDb = false;
	protected Socket connection;
	protected OutputStream sout; //socket output/input
	protected InputStream sin;
	protected final Object lockObject = new Object();//to synchronize one request at a time
	protected String username, password, host;
	protected int port;
	protected boolean ssl;

	protected abstract void writeCall(String methname, Object[] params) throws Exception;
	protected abstract Object readResp() throws Exception;

	/**
	 * Creates an RPC connection of the appropriate type and connection details
	 * @param type RPC type
	 * @param username
	 * @param password
	 * @param host IP address or hostname of RPC server
	 * @param port Port RPC server is operating on
	 * @param ssl Whether SSL is to be used
	 * @return A new RPC connection
	 * @throws MsfException
	 */
	public static RpcConnection getConn(String username, char[] password, String host, int port, boolean ssl) throws MsfException{
		RpcConnection conn = new MsgRpc();
		conn.setup(username, password, host, port, ssl);
		return conn;
	}

	/**
	 * Gets the unencoded data returned from a something.read call
	 * @param ret The return from the read call
	 * @return the 
	 */
	public static byte[] getData(Map received){
		if(received.containsKey("encoding") && received.get("encoding").equals("base64"))
			return Base64.decode(received.get("data").toString());
		else
			return received.get("data").toString().getBytes();
	}

	/** Setup sets up a connection and authenticates. */
	public void setup(String username, char[] password, String host, int port, boolean ssl) throws MsfException {
		boolean haveRpcd=false;
		this.username = username;
		this.password = new String(password);
		this.host = host;
		this.port = port;
		this.ssl = ssl;
		String message = "";
		try {
			connect();
			if(username == null || username.equals("")){
				rpcToken = this.password;
				execute("core.version"); //throws error if unsuccessful
				haveRpcd = true;
			}else{
				Map results = (Map)exec("auth.login",new Object[]{username, this.password});
				rpcToken=results.get("token").toString();
				haveRpcd=results.get("result").equals("success");
			}
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
	 * Disconnects this connection
	 *
	 * @throws SocketException
	 * @throws IOException
	 */
	protected void disconnect() throws SocketException, IOException{
		if(connection != null)
			connection.close();
	}

	/**
	 * Disconnects then reconnects.
	 *
	 * @throws SocketException
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	protected void reconnect() throws SocketException, KeyManagementException, IOException, NoSuchAlgorithmException {
		disconnect();
		connect();
	}

	/**
	 * Default connect method connects the TCP stream, setting up SSL if necessary.
	 *
	 * @throws SocketException
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	protected void connect() throws SocketException, KeyManagementException, IOException, NoSuchAlgorithmException {
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

	/** Method that handles synchronization and error handling for calls */
	private Object exec (String methname, Object[] params) throws MsfException{
		synchronized(lockObject){ //Only one method call at a time!
			try{
				writeCall(methname, params);
				return readResp();
			}catch(Exception ex){ //any weirdness gets wrapped in a MsfException
				try{
					if(ex instanceof java.net.SocketTimeoutException) 
						reconnect();  //reconnect on socket timeout
				}catch (Exception ex2){
					ex = ex2;
				}
				if(! (ex instanceof MsfException)){
					if(! MsfguiApp.shuttingDown || !ex.getLocalizedMessage().toLowerCase().contains("broken pipe")){
						if(!(ex instanceof java.net.ConnectException))
							ex.printStackTrace();
						throw new MsfException("Error in call: "+ex.getLocalizedMessage(), ex);
					}
				}
				throw (MsfException)ex;
			}
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
				String rpcType = "Basic";
				java.util.List args = new java.util.ArrayList(java.util.Arrays.asList(new String[]{
						"msfrpcd","-f","-P",defaultPass,"-t","Msg","-U",defaultUser,"-a","127.0.0.1",
						"-p",Integer.toString(defaultPort)}));
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
						myRpcConn = RpcConnection.getConn(defaultUser, defaultPass.toCharArray(), "127.0.0.1", defaultPort, defaultSsl);
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
				mainFrame.handleNewRpcConnection();
			}
		};
	}
}
