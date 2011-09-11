package msfgui;

import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.jdesktop.swingworker.SwingWorker;

/**
 * Window to interact with shells/meterpreters/consoles. Interacts with tab completion and holds command 
 * history. Also allows synchronization with other threads or windows interacting with the same console.
 * Only polls for output when open.
 * @author scriptjunkie
 */
public class InteractWindow extends MsfFrame implements ClipboardOwner {
	public final ReentrantLock lock = new ReentrantLock();
	private final Map session;
	private final RpcConnection rpcConn;
	private final String cmdPrefix;
	private String prompt;
	private Object sid;
	public static final char POLL = 'r';
	public static final char PAUSE = 'p';
	public static final char STOP_POLLING = 's';
	private final StringBuffer timerCommand;//synchronized mutable object as command placeholder for polling thread
	private final ArrayList commands;
	private int currentCommand = 0;

	/** Create a new console window to run a command */
	public static InteractWindow runCmdWindow(final RpcConnection rpcConn, final Map session, final String autoCommand){
		return new InteractWindow(rpcConn, session, java.util.Arrays.asList(new String[]{autoCommand}));
	}
	/** Create a new console window to run a module */
	public InteractWindow(final RpcConnection rpcConn, final Map session, final List autoCommands){
		this(rpcConn, session, "console");
		inputField.setEnabled(false);

		//start new thread auto
		new SwingWorker() {
			protected Object doInBackground() throws Exception {
				//for some reason the first command doesn't usually work. Do first command twice.
				try {
					if(autoCommands.get(0).toString().startsWith("use"))
						rpcConn.execute(cmdPrefix + "write", session.get("id"), autoCommands.get(0) + "\n");
				} catch (MsfException ex) {
					MsfguiApp.showMessage(null, ex);
				}
				for(Object cmd : autoCommands) {
					try {
						Thread.sleep(500);// Two commands a second
					} catch (InterruptedException iex) {
					}
					this.publish(cmd);
				}
				inputField.setEnabled(true);
				return null;
			}
			protected void process(List l){
				for(Object cmd : l){
					inputField.setText(cmd.toString());
					doInput();
				}
			}
		}.execute();
	}

	/** Creates a new window for interacting with shells/meterpreters/consoles */
	public InteractWindow(final RpcConnection rpcConn, final Map session, String type) {
		super(type+" interaction window");
		initComponents();
		loadSavedSize();
		this.rpcConn = rpcConn;
		this.session = session;
		sid = session.get("id");
		tabbedPane.setTitleAt(0, type+" "+sid);
		commands = new ArrayList();
		commands.add("");
		if(type.equals("console")) //console stuff
			cmdPrefix = "console.";
		else
			cmdPrefix = "session." + type + "_";
		inputField.setFocusTraversalKeysEnabled(false);
		//Add tab completion handler
		inputField.addKeyListener(new KeyAdapter(){
			public void keyTyped(KeyEvent ke) {
				//ignore other keys
				if(ke.getKeyChar() != '\t')
					return;
				Map res = (Map)rpcConn.execute(cmdPrefix+"tabs", sid,inputField.getText());
				List tabs = (List)res.get("tabs");
				//one option: use it
				if(tabs.size() == 1){
					inputField.setText(tabs.get(0).toString()+" ");
				//more options: display, and use common prefix
				} else if (tabs.size() > 1){
					String prefix = tabs.get(0).toString();
					for(Object o : tabs){
						String s = o.toString();
						int len = Math.min(s.length(), prefix.length());
						String newprefix = prefix;
						for(int i = 0; i < len && s.charAt(i) == prefix.charAt(i); i++)
							newprefix = prefix.substring(0,i+1);
						prefix = newprefix;
						outputArea.append("\n"+o.toString());
					}
					outputArea.append("\n");
					inputField.setText(prefix);
				}
			}
		});
		timerCommand = new StringBuffer(""+PAUSE);
		prompt = ">>>";

		//start new thread polling for input
		new SwingWorker() {
			protected Object doInBackground() throws Exception {
				long time = 100;
				while (timerCommand.charAt(0) != STOP_POLLING) {
					if (timerCommand.charAt(0)== PAUSE){
						synchronized(timerCommand){
							timerCommand.wait();
						}
						continue;
					}
					if (lock.tryLock() == false) {
						this.publish("locked");
						lock.lock();
						this.publish("unlocked");
					}
					try { //Get data, append to window, and send notification for prompt
						long start = System.currentTimeMillis();
						Map received = (Map) rpcConn.execute(cmdPrefix+"read",sid);
						time = System.currentTimeMillis() - start;
						byte[] decodedBytes = RpcConnection.getData(received);
						if (decodedBytes.length > 0) {
							outputArea.append(new String(decodedBytes));
							if(decodedBytes[decodedBytes.length-1] != '\n')
								outputArea.append("\n");//cause windows is just like that.
							publish("data");
						}
						publish(received);
					} catch (MsfException ex) {
						MsfguiApp.showMessage(null, ex);
						if(ex.getMessage().toLowerCase().contains("unknown session") // we're dead.
								|| !ex.getMessage().contains("timed out")) // on timeout, just retry
							timerCommand.setCharAt(0, STOP_POLLING);
					}
					lock.unlock();
					try {
						Thread.sleep(100 + (time * 3));// if it takes a long time to get data, ask for it slower
					} catch (InterruptedException iex) {
					}
				}
				return null;
			}
			protected void process(List l){
				for(Object o : l){
					if(o.equals("locked")){
						submitButton.setEnabled(false);
						inputField.setEditable(false);
					}else if(o.equals("unlocked")){
						submitButton.setEnabled(true);
						inputField.setEditable(true);
					}else if(o instanceof Map){ //Update prompt if received
						checkPrompt((Map)o);
					}else{ //Data printed, scroll to end
						outputArea.setCaretPosition(outputArea.getDocument().getLength());
					}
				}
			}
		}.execute();

		if(type.equals("meterpreter"))
			inputField.setText("help");
		outputArea.setFont(new Font("Monospaced", outputArea.getFont().getStyle(), outputArea.getFont().getSize()));
		checkPrompt(session);
		((DraggableTabbedPane)tabbedPane).setTabFocusListener(0, new FocusListener() {
			public void focusGained(FocusEvent e) {
				activate();
			}
			public void focusLost(FocusEvent e) {
				while(lock.getHoldCount() > 0)
					lock.unlock();
			}
		});
	}
	/** Also sets initial command */
	public InteractWindow(final RpcConnection rpcConn, final Map session, String type, String initVal) {
		this(rpcConn,session, type);
		inputField.setText(initVal);
	}
	/** Sets the prompt if provided */
	private void checkPrompt(Map o) {
		try{
			Object pobj = o.get("prompt");
			if (pobj == null)
				return;
			if(o.containsKey("encoding") && o.get("encoding").equals("base64"))
				prompt = new String(Base64.decode(pobj.toString()));
			else
				prompt = pobj.toString();
			StringBuilder sb = new StringBuilder();
			for(int i = 0; i < prompt.length(); i++)
				if(!Character.isISOControl(prompt.charAt(i)))
					sb.append(prompt.charAt(i));
			prompt=sb.toString();
			promptLabel.setText(prompt);
			submitButton.setEnabled(Boolean.FALSE.equals(o.get("busy")));
		}catch (MsfException mex){//bad prompt: do nothing
		}
	}

	private void doInput() {
		try {
			if(!submitButton.isEnabled())
				return;
			String command = inputField.getText();
			commands.add(command);
			rpcConn.execute(cmdPrefix + "write", session.get("id"), command + "\n");
			outputArea.append(prompt + command + "\n");
			outputArea.setCaretPosition(outputArea.getDocument().getLength());
			inputField.setText("");
			currentCommand = 0;
		} catch (MsfException ex) {
			MsfguiApp.showMessage(null, ex);
		}
	}
	/** This method is called from within the constructor to
	 * initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is
	 * always regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        tabbedPane = new DraggableTabbedPane(this);
        outputScrollPane = new javax.swing.JScrollPane();
        outputArea = new javax.swing.JTextArea();
        promptLabel = new javax.swing.JLabel();
        inputField = new javax.swing.JTextField();
        submitButton = new javax.swing.JButton();

        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowOpened(java.awt.event.WindowEvent evt) {
                formWindowOpened(evt);
            }
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
            public void windowActivated(java.awt.event.WindowEvent evt) {
                formWindowActivated(evt);
            }
        });

        tabbedPane.setName("tabbedPane"); // NOI18N

        mainPanel.setName("mainPanel"); // NOI18N

        outputScrollPane.setAutoscrolls(true);
        outputScrollPane.setName("outputScrollPane"); // NOI18N

        outputArea.setColumns(20);
        outputArea.setEditable(false);
        outputArea.setRows(5);
        outputArea.setName("outputArea"); // NOI18N
        outputScrollPane.setViewportView(outputArea);

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(InteractWindow.class);
        promptLabel.setText(resourceMap.getString("promptLabel.text")); // NOI18N
        promptLabel.setName("promptLabel"); // NOI18N

        inputField.setText(resourceMap.getString("inputField.text")); // NOI18N
        inputField.setName("inputField"); // NOI18N
        inputField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                inputFieldActionPerformed(evt);
            }
        });
        inputField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                inputFieldKeyPressed(evt);
            }
        });

        submitButton.setText(resourceMap.getString("submitButton.text")); // NOI18N
        submitButton.setName("submitButton"); // NOI18N
        submitButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                submitButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addComponent(promptLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(inputField, javax.swing.GroupLayout.DEFAULT_SIZE, 505, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(submitButton)
                .addContainerGap())
            .addComponent(outputScrollPane, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 619, Short.MAX_VALUE)
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addComponent(outputScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 459, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(promptLabel)
                    .addComponent(inputField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(submitButton))
                .addContainerGap())
        );

        tabbedPane.addTab(resourceMap.getString("mainPanel.TabConstraints.tabTitle"), mainPanel); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.DEFAULT_SIZE, 631, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.DEFAULT_SIZE, 551, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

	private void inputFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_inputFieldActionPerformed
		doInput();
	}//GEN-LAST:event_inputFieldActionPerformed

	private void submitButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_submitButtonActionPerformed
		inputFieldActionPerformed(evt);
	}//GEN-LAST:event_submitButtonActionPerformed

	private void inputFieldKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_inputFieldKeyPressed
		if(evt.getKeyCode() == KeyEvent.VK_UP){
			currentCommand = (currentCommand - 1 + commands.size()) % commands.size();
			inputField.setText(commands.get(currentCommand).toString());
		}else if(evt.getKeyCode() == KeyEvent.VK_DOWN){
			currentCommand = (currentCommand + 1) % commands.size();
			inputField.setText(commands.get(currentCommand).toString());
		}else if (evt.isControlDown()) {
			try {
				if (evt.getKeyCode() == KeyEvent.VK_C){
					String selText = outputArea.getSelectedText();
					if(selText != null && selText.length() > 0){
						Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(selText), this);
					}else{
						rpcConn.execute(cmdPrefix+"session_kill", session.get("id"));
					}
				}else  if (evt.getKeyCode() == KeyEvent.VK_Z){
					rpcConn.execute(cmdPrefix+"session_detach", session.get("id"));
					outputArea.append("backgrounding session...\n");
				}
			} catch (MsfException ex) {
				MsfguiApp.showMessage(null, ex);
			}
		}
	}//GEN-LAST:event_inputFieldKeyPressed

	private void formWindowOpened(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowOpened
		inputField.requestFocusInWindow();
	}//GEN-LAST:event_formWindowOpened

	private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
		timerCommand.setCharAt(0, PAUSE);
	}//GEN-LAST:event_formWindowClosing

	private void formWindowActivated(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowActivated
		activate();
	}//GEN-LAST:event_formWindowActivated

	/**
	 * Starts the polling process again
	 */
	public void activate(){
		timerCommand.setCharAt(0, POLL);
		synchronized(timerCommand){
			timerCommand.notify();
		}
	}

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField inputField;
    public final javax.swing.JPanel mainPanel = new javax.swing.JPanel();
    private javax.swing.JTextArea outputArea;
    private javax.swing.JScrollPane outputScrollPane;
    private javax.swing.JLabel promptLabel;
    private javax.swing.JButton submitButton;
    public javax.swing.JTabbedPane tabbedPane;
    // End of variables declaration//GEN-END:variables

	/** ok */
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}
}
