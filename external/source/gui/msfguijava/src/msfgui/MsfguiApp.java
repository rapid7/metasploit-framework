/*
 * MsfguiApp.java
 */

package msfgui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import org.jdesktop.application.Application;
import org.jdesktop.application.SingleFrameApplication;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * The main class of the application. Handles global settings and system functions.
 * @author scriptjunkie
 */
public class MsfguiApp extends SingleFrameApplication {
	public static final int NUM_REMEMBERED_MODULES = 20;
	private static Element propRoot;
	private static List recentList = null;
	public static JFileChooser fileChooser;
	protected static Pattern backslash = Pattern.compile("\\\\");
	public static String workspace = "default";
	public static final String confFilename = System.getProperty("user.home")+File.separatorChar+".msf3"+File.separatorChar+"msfgui";

	static{ //get saved properties file
		propRoot = null;
		try{
			propRoot = DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.parse(new File(confFilename)).getDocumentElement();
		} catch (Exception ex) { //if anything goes wrong, make new (IOException, SAXException, ParserConfigurationException, NullPointerException
			propRoot = getPropertiesNode();//ensure existence
		}
		Runtime.getRuntime().addShutdownHook(new Thread(){
			@Override
			public void run() {
				//Output the XML
				try{
					if(recentList != null){ //if we have a new list to save
						//save recent
						for(Node node = propRoot.getFirstChild(); node != null; node = node.getNextSibling())
							if(node.getNodeName().equals("recent"))
								propRoot.removeChild(node);
						Document doc = propRoot.getOwnerDocument();
						Node recentNode = doc.createElement("recent");
						for(Object o : recentList){
							Object[] args = (Object[])o;
							Element recentItem = doc.createElement("recentItem");
							recentItem.setAttribute("moduleType",args[0].toString());
							recentItem.setAttribute("fullName",args[1].toString());
							for(Object p : ((Map)args[2]).entrySet()){
								Map.Entry prop = (Map.Entry)p;
								Element propItem = doc.createElement(prop.getKey().toString());
								propItem.setAttribute("val",prop.getValue().toString());
								recentItem.appendChild(propItem);
							}
							recentNode.appendChild(recentItem);
						}
						propRoot.appendChild(recentNode);
					}
					TransformerFactory.newInstance().newTransformer().transform(
							new DOMSource(propRoot), new StreamResult(new FileOutputStream(confFilename)));
				}catch (Exception ex){
				}
			}
		});
	}

	/**
	 * At startup create and show the main frame of the application.
	 */
	@Override protected void startup() {
		MsfguiLog.initDefaultLog();
		show(new MainFrame(this));
	}

	/**
	 * This method is to initialize the specified window by injecting resources.
	 * Windows shown in our application come fully initialized from the GUI
	 * builder, so this additional configuration is not needed.
	 */
	@Override protected void configureWindow(java.awt.Window root) {
	}

	/**
	 * A convenient static getter for the application instance.
	 * @return the instance of MsfguiApp
	 */
	public static MsfguiApp getApplication() {
		return Application.getInstance(MsfguiApp.class);
	}

	/**
	 * Main method launching the application.
	 */
	public static void main(String[] args) {
		launch(MsfguiApp.class, args);
	}

	/** Application helper to launch msfrpcd or msfencode, etc. */
	public static Process startMsfProc(List command) throws MsfException{
		String[] args = new String[command.size()];
		for(int i = 0; i < args.length; i++)
			args[i] = command.get(i).toString();
		return startMsfProc(args);
	}
	/** Application helper to launch msfrpcd or msfencode, etc. */
	public static Process startMsfProc(String[] args) throws MsfException {
		String msfCommand = args[0];
		String prefix;
		try{
			prefix = getPropertiesNode().getAttributeNode("commandPrefix").getValue();
		}catch(Exception ex){
			prefix = "";
		}
		Process proc;
		String[] winArgs = null;
		try {
			args[0] = prefix + msfCommand;
			proc = Runtime.getRuntime().exec(args);
		} catch (Exception ex1) {
			try {
				proc = Runtime.getRuntime().exec(args);
			} catch (IOException ex2) {
				try {
					args[0] = "/opt/metasploit3/msf3/" + msfCommand;
					proc = Runtime.getRuntime().exec(args);
				} catch (IOException ex3) {
					try {
						winArgs = new String[args.length + 3];
						System.arraycopy(args, 0, winArgs, 3, args.length);
						winArgs[0] = "cmd";
						winArgs[1] = "/c";
						File dir = new File(System.getenv("PROGRAMFILES") + "\\Metasploit\\Framework3\\bin\\");
						if (msfCommand.equals("msfencode"))
							winArgs[2] = "ruby.exe";
						else
							winArgs[2] = "rubyw.exe";
						winArgs[3] = "/msf3/" + msfCommand;
						proc = Runtime.getRuntime().exec(winArgs, null, dir);
					} catch (IOException ex4) {
						try {
							File dir = new File(System.getenv("PROGRAMFILES(x86)")
									+ "\\Metasploit\\Framework3\\bin\\");
							proc = Runtime.getRuntime().exec(winArgs, null, dir);
						} catch (IOException ex5) {
							try {
								File dir = new File(prefix);
								proc = Runtime.getRuntime().exec(winArgs, null, dir);
							} catch (IOException ex6) {
								throw new MsfException("Executable not found for "+msfCommand);
							}
						}
					}
				}
			}
		}
		return proc;
	}

	/** Get root node of xml saved options file */
	public static Element getPropertiesNode(){
		if(propRoot == null){
			try {
				Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
				Element root = doc.createElement("root");
				doc.appendChild(root);
				propRoot = root;
			} catch (ParserConfigurationException ex) {
				JOptionPane.showMessageDialog(null,"Error saving properties. Cannot make new properties node.");
			}
		}
		return propRoot;
	}

	/** Adds a module run to the recent modules list */
	public static void addRecentModule(final Object[] args, final RpcConnection rpcConn, final MainFrame mf) {
		final JMenu recentMenu = mf.recentMenu;
		if(recentList == null)
			recentList = new LinkedList();
		recentList.add(args);
		Map hash = (Map)args[2];
		StringBuilder name = new StringBuilder(args[0] + " " + args[1]);
		for(Object ento : hash.entrySet()){
			Entry ent = (Entry)ento;
			String propName = ent.getKey().toString();
			if(propName.endsWith("HOST") || propName.endsWith("PORT") || propName.equals("PAYLOAD"))
				name.append(" "+propName+"-"+ent.getValue());
		}
		final JMenuItem item = new JMenuItem(name.toString());
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				new ModulePopup(rpcConn, args, mf).setVisible(true);
				recentMenu.remove(item);
				recentMenu.add(item);
				for(int i = 0; i < recentList.size(); i++){
					if(Arrays.equals((Object[])recentList.get(i), args)){
						recentList.add(recentList.remove(i));
						break;
					}
				}
			}
		});
		recentMenu.add(item);
		recentMenu.setEnabled(true);
		if(recentMenu.getItemCount() > NUM_REMEMBERED_MODULES)
			recentMenu.remove(0);
		if(recentList.size() > NUM_REMEMBERED_MODULES)
			recentList.remove(0);
	}
	public static void addRecentModules(final RpcConnection rpcConn, final MainFrame mf) {
		Node recentNode = null;
		for(Node node = propRoot.getFirstChild(); node != null; node = node.getNextSibling())
			if(node.getNodeName().equals("recent"))
				recentNode = node;
		
		if(recentNode == null)
			return;
		NodeList recentItems = recentNode.getChildNodes();
		int len = recentItems.getLength();
		for(int i = 0; i < len; i++){
			HashMap hash = new HashMap();
			Node recentItem = recentItems.item(i);

			try{
				String moduleType = recentItem.getAttributes().getNamedItem("moduleType").getNodeValue();
				String fullName = recentItem.getAttributes().getNamedItem("fullName").getNodeValue();

				NodeList recentItemProps = recentItem.getChildNodes();
				int propslen = recentItemProps.getLength();
				for(int j = 0; j < propslen; j++){
					Node prop = recentItemProps.item(j);
					String propName = prop.getNodeName();
					String val = prop.getAttributes().getNamedItem("val").getNodeValue();
					hash.put(propName, val);
				}
				addRecentModule(new Object[]{moduleType, fullName,hash}, rpcConn, mf);
			}catch(NullPointerException nex){//if attribute doesn't exist, ignore
			}
		}
	}

	/** Clear history of run modules */
	public static void clearHistory(JMenu recentMenu){
		recentList.clear();
		recentMenu.removeAll();
		recentMenu.setEnabled(false);
	}

	/** Gets a temp file from system */
	public static String getTempFilename(String prefix, String suffix) {
		try{
			final File temp = File.createTempFile(prefix, suffix);
			String path = temp.getAbsolutePath();
			temp.delete();
			return path;
		}catch(IOException ex){
			JOptionPane.showMessageDialog(null, "Cannot create temp file. This is a bad and unexpected error. What is wrong with your system?!");
			return null;
		}
	}

	/** Gets a temp folder from system */
	public static String getTempFolder() {
		try{
			final File temp = File.createTempFile("abcde", ".bcde");
			String path = temp.getParentFile().getAbsolutePath();
			temp.delete();
			return path;
		}catch(IOException ex){
			JOptionPane.showMessageDialog(null, "Cannot create temp file. This is a bad and unexpected error. What is wrong with your system?!");
			return null;
		}
	}

	/** Returns the likely local IP address for talking to the world */
	public static String getLocalIp(){
		try{
			DatagramSocket socket = new DatagramSocket();
			socket.connect(InetAddress.getByName("1.2.3.4"),1234);
			socket.getLocalAddress();
			String answer = socket.getLocalAddress().getHostAddress();
			socket.close();
			return answer;
		} catch(IOException ioe){
			try{
				return InetAddress.getLocalHost().getHostAddress();
			}catch (UnknownHostException uhe){
				return "127.0.0.1";
			}
		}
	}

	public static String cleanBackslashes(String input){
		return backslash.matcher(input).replaceAll("/");
	}
	public static String doubleBackslashes(String input){
		return backslash.matcher(input).replaceAll("\\\\\\\\");
	}
}
