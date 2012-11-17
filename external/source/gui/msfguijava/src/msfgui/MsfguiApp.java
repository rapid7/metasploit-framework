package msfgui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
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
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;

/**
 * The main class of the application. Handles global settings and system functions.
 * @author scriptjunkie
 */
public class MsfguiApp extends SingleFrameApplication {
	public static final int NUM_REMEMBERED_MODULES = 20;
	private static final Map propRoot;
	public static JFileChooser fileChooser;
	protected static Pattern backslash = Pattern.compile("\\\\");
	public static String workspace = "default";
	public static final String confFilename = System.getProperty("user.home")+File.separatorChar+".msf4"+File.separatorChar+"msfgui";
	public static MainFrame mainFrame;
	public static boolean shuttingDown = false;

	static{
		//First start detection
		if(!(new java.io.File(confFilename)).exists()){
			try{
				//Prepare exit rc
				String rcname = MsfguiApp.getTempFilename("exit", ".rc");
				FileWriter exitOut = new FileWriter(rcname);
				exitOut.write("exit\n");
				exitOut.close();
				Process p;
				//Run msfconsole once to init database.
				if(System.getProperty("os.name").toLowerCase().contains("windows")){
					ProcessBuilder ps = new ProcessBuilder(new String[]{"console.exe","-c",
							System.getenv("BASE")+"tools\\console.xml","-t","Metasploit"});
					ps.environment().put("MSFCONSOLE_OPTS", "-e production -y \""+
							System.getenv("BASE")+"config\\database.yml\" -r "+rcname);
					ps.directory(new File(System.getenv("BASE")));
					p = ps.start();
				}else{
					p = startMsfProc(new String[]{"msfconsole","-r",rcname});
				}
				//Tell user and wait
				JOptionPane.showMessageDialog(null, "Please wait for msf4 first-run initialization");
				p.waitFor();
			}catch(Exception iox){
				JOptionPane.showMessageDialog(null, "First-run initialization failed: "+iox.getMessage());
			}
		}
		//get saved properties file
		Map props;
		try{
			props = (Map)XmlRpc.parseVal(DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.parse(new FileInputStream(confFilename)).getDocumentElement());
		} catch (Exception ex) { //if anything goes wrong, make new (IOException, SAXException, ParserConfigurationException, NullPointerException
			props = new HashMap();//ensure existence
		}
		propRoot = props;
		RpcConnection.disableDb = Boolean.TRUE.equals(propRoot.get("disableDb")); //restore this, since it can't be checked on connect
		if(propRoot.get("recentList") == null)
			propRoot.put("recentList", new LinkedList());
		Runtime.getRuntime().addShutdownHook(new Thread(){
			@Override
			public void run() {
				savePreferences();
			}
		});
	}
	public static void showMessage(java.awt.Component parent, Object message){
		String msg = message.toString();
		if(!shuttingDown && !msg.toLowerCase().contains("unknown session"))
			JOptionPane.showMessageDialog(parent, message);
	}

	/**
	 * Saves the properties node as an XML file specified by confFilename
	 */
	public static void savePreferences(){
		try {
			Document docElement = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			docElement.appendChild(XmlRpc.objectToNode(docElement, propRoot));
			TransformerFactory.newInstance().newTransformer().transform(new DOMSource(docElement), new StreamResult(new FileOutputStream(confFilename)));
		} catch (Exception ex) {
			//fail
			try {
				//Problem saving conf file; we are probably closing here, so we shouldn't try to pop up a message box
				FileWriter fout = new FileWriter(confFilename + "ERROR.log", true);
				fout.write(java.util.Calendar.getInstance().getTime().toString());
				fout.write(" Error saving properties. Check " + confFilename + " file permissions.\n");
				fout.write(ex.toString() + "\n");
				fout.close();
			} catch (Exception exc) {
				//epic fail
			}
		}
	}

	/**
	 * At startup create and show the main frame of the application.
	 */
	@Override protected void startup() {
		MsfguiLog.initDefaultLog();
		mainFrame = new MainFrame(this);
		show(mainFrame);
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
		return startMsfProc((String[])command.toArray(new String[command.size()]));
	}
	/** Application helper to launch msfrpcd or msfencode, etc. */
	public static Process startMsfProc(String[] args) throws MsfException {
		String msfCommand = args[0];
		String prefix;
		File msfRoot = getMsfRoot();
		try{
			prefix = getPropertiesNode().get("commandPrefix").toString();
		}catch(Exception ex){
			prefix = "";
		}
		Process proc;
		String[] winArgs = null;
		try {
			args[0] = prefix + msfCommand;
			proc = Runtime.getRuntime().exec(args, null, msfRoot);
		} catch (Exception ex1) {
			try {
				proc = Runtime.getRuntime().exec(args, null, msfRoot);
			} catch (IOException ex2) {
				try {
					args[0] = msfRoot + "/" + msfCommand;
					proc = Runtime.getRuntime().exec(args, null, msfRoot);
				} catch (IOException ex3) {
					try {
						winArgs = new String[args.length + 3];
						System.arraycopy(args, 0, winArgs, 3, args.length);
						winArgs[0] = "cmd";
						winArgs[1] = "/c";
						winArgs[2] = "ruby.exe";
						winArgs[3] = msfCommand;
						proc = Runtime.getRuntime().exec(winArgs, null, msfRoot);
					} catch (IOException ex4){
						try{
							if (msfCommand.equals("msfencode"))
								winArgs[2] = "ruby.exe";
							else
								winArgs[2] = "rubyw.exe";
							winArgs[3] = msfRoot + "/"  + msfCommand;
							proc = Runtime.getRuntime().exec(winArgs);
						} catch (IOException ex5) {
							try {
								File dir = new File(prefix);
								winArgs[3] = msfCommand;
								proc = Runtime.getRuntime().exec(winArgs, null, dir);
							} catch (IOException ex7) {
								throw new MsfException("Executable not found for "+msfCommand);
							}
						}
					}
				}
			}
		}
		return proc;
	}

	/**
	 * Runs the specified module from options provided, sending results to main frame
	 * @param console
	 * @param hash
	 * @throws MsfException
	 * @throws HeadlessException
	 */
	public static void runModule(String moduleType, String fullName, Map hash, RpcConnection rpcConn,
			MainFrame parentFrame, boolean console) throws MsfException, java.awt.HeadlessException {
		//Execute and get results
		if (console) { // Create a list of commands to run in the console
			Map res = (Map) rpcConn.execute("console.create");
			java.util.ArrayList autoCommands = new java.util.ArrayList();
			autoCommands.add("use " + moduleType + "/" + fullName);
			//Add target if it is set and not zero if there is no default or non-default if there is a default
			if(moduleType.equals("exploit") && hash.containsKey("TARGET")){
				Map info = (Map) rpcConn.execute("module.info", moduleType, fullName);
				if(info.containsKey("default_target") && !hash.get("TARGET").toString().equals(info.get("default_target").toString())
						|| !info.containsKey("default_target") && !hash.get("TARGET").toString().equals("0"))
					autoCommands.add("set TARGET " + hash.get("TARGET"));
			}
			if (hash.containsKey("PAYLOAD"))
				autoCommands.add("set PAYLOAD " + hash.get("PAYLOAD"));
			//Convert the rest of the options to set commands
			for (Object entObj : hash.entrySet()) {
				Map.Entry ent = (Map.Entry) entObj;
				if (!(ent.getKey().toString().equals("TARGET")) && !(ent.getKey().toString().equals("PAYLOAD")))
					autoCommands.add("set " + ent.getKey() + " " + MsfguiApp.escapeBackslashes(ent.getValue().toString()));
			}
			autoCommands.add("exploit");
			InteractWindow iw = new InteractWindow(rpcConn, res, autoCommands);
			parentFrame.registerConsole(res, true, iw);
			MsfguiLog.defaultLog.logMethodCall("module.execute", new Object[]{moduleType, fullName, hash});
		} else { // Non-console; just fire away
			Map info = (Map) rpcConn.execute("module.execute",moduleType, fullName,hash);
			if (!info.containsKey("job_id") && !info.get("result").equals("success"))
				MsfguiApp.showMessage(parentFrame.getFrame(), info);
		}
		MsfguiApp.addRecentModule(java.util.Arrays.asList(new Object[]{moduleType, fullName, hash}), rpcConn, parentFrame);
	}

	/** Get root node of xml saved options file */
	public static Map getPropertiesNode(){
		return propRoot;
	}
	/**
	 * Finds the path to the root of the metasploit tree (the msf3 folder this jar is being run out of)
	 * @return A File object pointing to the directory at the root of the metasploit tree
	 * @throws MsfException if this jar file has been moved or the containing directory structure has been moved.
	 */
	public static File getMsfRoot() throws MsfException{
		try{
			File f = new File(MsfguiApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
			File parent = f.getParentFile();
			File grandparent = parent.getParentFile();
			if(f.getName().equals("msfgui.jar") && parent.getName().equals("gui") &&  grandparent.getName().equals("data"))
				return grandparent.getParentFile();
		}catch(java.net.URISyntaxException urisex){
			urisex.printStackTrace();
		}
		throw new MsfException("Cannot find path.");
	}

	/** Adds a module run to the recent modules list */
	public static void addRecentModule(final List args, final RpcConnection rpcConn, final MainFrame mf) {
		addRecentModule(args, rpcConn, mf, true);
	}
	public static void addRecentModule(final List args, final RpcConnection rpcConn, final MainFrame mf, boolean ignoreDups) {
		final JMenu recentMenu = mf.recentMenu;
		List recentList = (List)propRoot.get("recentList");
		if(recentList.contains(args)){
			if(ignoreDups)
				return;
		}else{
			recentList.add(args);
		}
		Map hash = (Map)args.get(2);
		StringBuilder name = new StringBuilder(args.get(0) + " " + args.get(1));
		//Save these options
		if(!propRoot.containsKey("modOptions")) //first ensure option map exists
			propRoot.put("modOptions", new HashMap());
		((Map)propRoot.get("modOptions")).put(name.toString(), args);

		//Generate display name
		for(Object ento : hash.entrySet()){
			Entry ent = (Entry)ento;
			String propName = ent.getKey().toString();
			if(propName.endsWith("HOST") || propName.endsWith("PORT") || propName.equals("PAYLOAD"))
				name.append(" ").append(propName).append("-").append(ent.getValue());
		}
		//Make menu item
		final JMenuItem item = new JMenuItem(name.toString());
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				new ModulePopup(rpcConn, args.toArray(), mf).setVisible(true);
				recentMenu.remove(item);
				recentMenu.add(item);
				List recentList = (List)propRoot.get("recentList");
				for(int i = 0; i < recentList.size(); i++){
					if(recentList.get(i).equals(args)){
						recentList.add(recentList.remove(i));
						break;
					}
				}
			}
		});
		MsfFrame.updateSizes(item);
		recentMenu.add(item);
		recentMenu.setEnabled(true);
		if(recentMenu.getItemCount() > NUM_REMEMBERED_MODULES)
			recentMenu.remove(0);
		if(recentList.size() > NUM_REMEMBERED_MODULES)
			recentList.remove(0);
	}
	public static void addRecentModules(final RpcConnection rpcConn, final MainFrame mf) {
		List recentList = (List)propRoot.get("recentList");
		for(Object item : recentList)
			addRecentModule((List)item, rpcConn, mf, false);
	}

	/** Clear history of run modules */
	public static void clearHistory(JMenu recentMenu){
		((List)propRoot.get("recentList")).clear();
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
			MsfguiApp.showMessage(null, "Cannot create temp file. This is a bad and unexpected error. What is wrong with your system?!");
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
			MsfguiApp.showMessage(null, "Cannot create temp file. This is a bad and unexpected error. What is wrong with your system?!");
			return null;
		}
	}

	/** Returns the likely local IP address for talking to the world */
	public static String getLocalIp(){
		try{
			DatagramSocket socket = new DatagramSocket();
			socket.connect(InetAddress.getByName("1.2.3.4"),1234);
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
	public static String escapeBackslashes(String input){
		StringBuilder output = new StringBuilder();
		for(char c : input.toCharArray()){
			if(c == '\\' || c == ' ' || c == '\'' || c == '"')
				output.append('\\');
			output.append(c);
		}
		return output.toString();
	}
}
