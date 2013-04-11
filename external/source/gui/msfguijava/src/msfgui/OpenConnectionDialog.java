package msfgui;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

/**
 * Options dialog for opening a connection the rpc daemon
 * @author scriptjunkie
 */
public class OpenConnectionDialog extends javax.swing.JDialog {
	private MainFrame mainframe;
	private RpcConnection rpcConn;
	private int timeout = 4;
	private javax.swing.Timer countdown;

	/** Creates new form UserPassDialog */
	public OpenConnectionDialog(boolean modal, MainFrame mainframe) {
		super(mainframe.getFrame(), modal);
		this.mainframe = mainframe;
		initComponents();
		setTitle("msfgui");
		org.jdesktop.application.ResourceMap resourceMap 
				= org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class)
				.getContext().getResourceMap(ModulePopup.class);
		this.setIconImage(resourceMap.getImageIcon("main.icon").getImage());

		startNewButton.requestFocusInWindow();
		startNewButton.addFocusListener(new FocusListener(){
			public void focusGained(FocusEvent fe) {
			}
			public void focusLost(FocusEvent fe) {
				timeout = 0;
				startNewButton.setText("Start new msfrpcd");
			}
		});
		countdown = new javax.swing.Timer(1000,new ActionListener(){
			public void actionPerformed(ActionEvent ae) {
				if(timeout == 0){
					countdown.stop();
					return;
				}
				timeout = timeout - 1;
				startNewButton.setText("Start new msfrpcd ("+timeout+")");
				if(timeout == 0)
					startNewButtonActionPerformed(ae);
			}
		});
		countdown.start();
		startNewButton.setText("Start new msfrpcd ("+timeout+")");
		Map root = MsfguiApp.getPropertiesNode();
		fillDefault(root.get("username"),usernameField);
		fillDefault(root.get("host"),hostField);
		fillDefault(root.get("port"),portField);
		sslBox.setSelected(Boolean.TRUE.equals(root.get("ssl")));
		disableDbButton.setSelected(Boolean.TRUE.equals(root.get("disableDb")));
	}

	private boolean checkCrypto(boolean ssl) throws MsfException {
		try {
			if (ssl)
				javax.crypto.KeyGenerator.getInstance("SunTlsRsaPremasterSecret");
		} catch (NoSuchAlgorithmException nsax) {
			int res = JOptionPane.showConfirmDialog(this, "Error: this version of Java may not support the necessary "
					+ "\ncryptographic capabilities to connect to msfrpcd over SSL. Try running \n"
					+ (System.getProperty("os.name").toLowerCase().contains("windows") ? "" : "java -jar ")
					+ MsfguiApp.getMsfRoot() + "/data/gui/msfgui.jar \n"
					+ "as your system version of Java may work.\n\nContinue anyway?");
			if(res != JOptionPane.YES_OPTION)
				throw new MsfException("SSLcheck", nsax);
		}
		return ssl;
	}

	/** Sets the text of the given component if val is defined */
	private void fillDefault(Object val, JTextField field) {
		if (val!= null)
			field.setText(val.toString());
	}

	/** Gets a connection for a main window from saved credentials or via the open
	 * connection dialog.
	 * @param mainframe the parent frame
	 * @return the new connection
	 */
	public static RpcConnection getConnection(MainFrame mainframe) {
		if(mainframe.rpcConn != null){
			MsfguiApp.showMessage(mainframe.getFrame(), "You are already connected!\n"
					+ "Exit before making a new connection.");
			throw new RuntimeException("Already connected");
		}
		//try saved connection credentials
		try{
			Map info = MsfguiApp.getPropertiesNode();
			String username = info.get("username").toString();
			String password = info.get("password").toString();
			String host = info.get("host").toString();
			int port = Integer.parseInt(info.get("port").toString());
			boolean ssl = Boolean.parseBoolean(info.get("ssl").toString());
			RpcConnection rpc = RpcConnection.getConn(username, password.toCharArray(), host, port, ssl);
			if(javax.swing.JOptionPane.showConfirmDialog(null, "Connect to last remembered rpcd?") == javax.swing.JOptionPane.YES_OPTION)
				return rpc;
			rpc.execute("auth.logout");
		} catch (MsfException mex) {
			if(mex.getMessage().toLowerCase().contains("authentication error"))
				mainframe.statusAnimationLabel.setText("Error authenticating; msfrpcd is running "
						+"but you did not enter the right credentials.");
			else if (mex.getMessage().toLowerCase().contains("connection reset"))
				mainframe.statusAnimationLabel.setText("Connection reset; is the SSL option correct?"
						+ " Is msfrpcd running on the right port?");
			else if (mex.getMessage().toLowerCase().contains("timed out"))
				mainframe.statusAnimationLabel.setText("Timeout; is the SSL option correct?"
						+ " Is msfrpcd running on the right port?");
		} catch (NullPointerException nex) {//generated when attributes dont exist.
		} catch (Exception ex) { //for weird msg exceptions
		}
		//Try service token on default 3790
		BufferedReader fin = null;
		try{
			try{
				fin = new BufferedReader(new FileReader(MsfguiApp.getMsfRoot().getParent()+"/apps/pro/engine/tmp/servicekey.txt"));
			}catch(Exception iox2){
				fin = new BufferedReader(new FileReader("/opt/metasploit/apps/pro/engine/tmp/servicekey.txt"));
			}
			RpcConnection rpc = RpcConnection.getConn("", fin.readLine().toCharArray(), "localhost", 3790, true);
			if(javax.swing.JOptionPane.showConfirmDialog(null, "Connect to local rpcd?") == javax.swing.JOptionPane.YES_OPTION)
				return rpc;
		}catch(Exception iox){//file not found/unreadable/bad creds/etc. - ignore
		}
		//Darn. open the gui anyway
		OpenConnectionDialog diag = new OpenConnectionDialog(true, mainframe);
		diag.setVisible(true);
		return diag.rpcConn;
	}

	/** This method is called from within the constructor to
	 * initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is
	 * always regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        titleLabel = new javax.swing.JLabel();
        usernameLabel = new javax.swing.JLabel();
        passwordLabel = new javax.swing.JLabel();
        hostLabel = new javax.swing.JLabel();
        portLabel = new javax.swing.JLabel();
        usernameField = new javax.swing.JTextField();
        passwordField = new javax.swing.JPasswordField();
        hostField = new javax.swing.JTextField();
        portField = new javax.swing.JTextField();
        connectButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        startNewButton = new javax.swing.JButton();
        pathButton = new javax.swing.JButton();
        sslBox = new javax.swing.JCheckBox();
        sslLabel = new javax.swing.JLabel();
        disableDbLabel = new javax.swing.JLabel();
        disableDbButton = new javax.swing.JCheckBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(OpenConnectionDialog.class);
        setTitle(resourceMap.getString("Form.title")); // NOI18N

        titleLabel.setText(resourceMap.getString("titleLabel.text")); // NOI18N
        titleLabel.setName("titleLabel"); // NOI18N

        usernameLabel.setText(resourceMap.getString("usernameLabel.text")); // NOI18N
        usernameLabel.setName("usernameLabel"); // NOI18N

        passwordLabel.setText(resourceMap.getString("passwordLabel.text")); // NOI18N
        passwordLabel.setName("passwordLabel"); // NOI18N

        hostLabel.setText(resourceMap.getString("hostLabel.text")); // NOI18N
        hostLabel.setName("hostLabel"); // NOI18N

        portLabel.setText(resourceMap.getString("portLabel.text")); // NOI18N
        portLabel.setName("portLabel"); // NOI18N

        usernameField.setText(resourceMap.getString("usernameField.text")); // NOI18N
        usernameField.setName("usernameField"); // NOI18N
        usernameField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                usernameFieldActionPerformed(evt);
            }
        });

        passwordField.setText(resourceMap.getString("passwordField.text")); // NOI18N
        passwordField.setName("passwordField"); // NOI18N
        passwordField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passwordFieldActionPerformed(evt);
            }
        });

        hostField.setText(resourceMap.getString("hostField.text")); // NOI18N
        hostField.setName("hostField"); // NOI18N
        hostField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hostFieldActionPerformed(evt);
            }
        });

        portField.setText(resourceMap.getString("portField.text")); // NOI18N
        portField.setName("portField"); // NOI18N
        portField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                portFieldActionPerformed(evt);
            }
        });

        connectButton.setFont(connectButton.getFont());
        connectButton.setText(resourceMap.getString("connectButton.text")); // NOI18N
        connectButton.setName("connectButton"); // NOI18N
        connectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });

        cancelButton.setFont(cancelButton.getFont());
        cancelButton.setText(resourceMap.getString("cancelButton.text")); // NOI18N
        cancelButton.setName("cancelButton"); // NOI18N
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        startNewButton.setFont(startNewButton.getFont().deriveFont(startNewButton.getFont().getStyle() | java.awt.Font.BOLD));
        startNewButton.setText(resourceMap.getString("startNewButton.text")); // NOI18N
        startNewButton.setName("startNewButton"); // NOI18N
        startNewButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                startNewButtonActionPerformed(evt);
            }
        });

        pathButton.setText(resourceMap.getString("pathButton.text")); // NOI18N
        pathButton.setName("pathButton"); // NOI18N
        pathButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pathButtonActionPerformed(evt);
            }
        });

        sslBox.setText(resourceMap.getString("sslBox.text")); // NOI18N
        sslBox.setName("sslBox"); // NOI18N

        sslLabel.setText(resourceMap.getString("sslLabel.text")); // NOI18N
        sslLabel.setName("sslLabel"); // NOI18N

        disableDbLabel.setText(resourceMap.getString("disableDbLabel.text")); // NOI18N
        disableDbLabel.setName("disableDbLabel"); // NOI18N

        disableDbButton.setText(resourceMap.getString("disableDbButton.text")); // NOI18N
        disableDbButton.setName("disableDbButton"); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(titleLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(sslLabel)
                            .addComponent(hostLabel)
                            .addComponent(passwordLabel)
                            .addComponent(portLabel)
                            .addComponent(disableDbLabel)
                            .addComponent(usernameLabel))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(disableDbButton)
                            .addComponent(usernameField, javax.swing.GroupLayout.DEFAULT_SIZE, 433, Short.MAX_VALUE)
                            .addComponent(hostField, javax.swing.GroupLayout.DEFAULT_SIZE, 433, Short.MAX_VALUE)
                            .addComponent(passwordField, javax.swing.GroupLayout.DEFAULT_SIZE, 433, Short.MAX_VALUE)
                            .addComponent(portField, javax.swing.GroupLayout.DEFAULT_SIZE, 433, Short.MAX_VALUE)
                            .addComponent(sslBox)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(startNewButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pathButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 132, Short.MAX_VALUE)
                        .addComponent(cancelButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(connectButton)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(titleLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(usernameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(usernameLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(passwordLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(hostLabel)
                    .addComponent(hostField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(portField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(portLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(sslBox, javax.swing.GroupLayout.Alignment.LEADING, 0, 0, Short.MAX_VALUE)
                    .addComponent(sslLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(disableDbLabel)
                    .addComponent(disableDbButton, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(connectButton, javax.swing.GroupLayout.DEFAULT_SIZE, 37, Short.MAX_VALUE)
                    .addComponent(cancelButton, javax.swing.GroupLayout.DEFAULT_SIZE, 37, Short.MAX_VALUE)
                    .addComponent(startNewButton, javax.swing.GroupLayout.DEFAULT_SIZE, 37, Short.MAX_VALUE)
                    .addComponent(pathButton, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

	private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed
		String username = usernameField.getText();
		char[] password = passwordField.getPassword();
		String host = hostField.getText();
		int port = Integer.parseInt(portField.getText());
		boolean ssl = checkCrypto(sslBox.isSelected());
		try {
			rpcConn = RpcConnection.getConn(username, password, host, port, ssl);
		} catch (MsfException mex) {
			rpcConn = null;
		}
		setVisible(false);
	}//GEN-LAST:event_connectButtonActionPerformed

	private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
		rpcConn = null;
		setVisible(false);
	}//GEN-LAST:event_cancelButtonActionPerformed

	private void usernameFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_usernameFieldActionPerformed
		connectButtonActionPerformed(evt);
	}//GEN-LAST:event_usernameFieldActionPerformed

	private void passwordFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passwordFieldActionPerformed
		connectButtonActionPerformed(evt);
	}//GEN-LAST:event_passwordFieldActionPerformed

	private void hostFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hostFieldActionPerformed
		connectButtonActionPerformed(evt);
	}//GEN-LAST:event_hostFieldActionPerformed

	private void portFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_portFieldActionPerformed
		connectButtonActionPerformed(evt);
	}//GEN-LAST:event_portFieldActionPerformed

	private void startNewButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_startNewButtonActionPerformed
		//Setup defaults
		RpcConnection.defaultUser = usernameField.getText();
		if(passwordField.getPassword().length > 0)
			RpcConnection.defaultPass = new String(passwordField.getPassword());
		if(hostField.getText().length() > 0)
			RpcConnection.defaultHost = hostField.getText();
		RpcConnection.defaultPort  = Integer.parseInt(portField.getText());
		RpcConnection.defaultSsl = checkCrypto(sslBox.isSelected());
		RpcConnection.disableDb = disableDbButton.isSelected();
		//do the action. There's probably a "right" way to do  Oh well.
		mainframe.getContext().getActionMap(mainframe).get("startRpc").actionPerformed(new java.awt.event.ActionEvent(startNewButton,1234,""));
		setVisible(false);
	}//GEN-LAST:event_startNewButtonActionPerformed

	private void pathButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pathButtonActionPerformed
		File dir =new File("/opt/metasploit3/msf3/");
		if(dir.isDirectory())
			MsfguiApp.fileChooser.setCurrentDirectory(dir);
		if(MsfguiApp.getPropertiesNode().get("commandPrefix") != null)
			dir =new File(MsfguiApp.getPropertiesNode().get("commandPrefix").toString());
		if(dir.isDirectory())
			MsfguiApp.fileChooser.setCurrentDirectory(dir);
		if (MsfguiApp.fileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
			return;
		MsfguiApp.getPropertiesNode().put("commandPrefix",
				MsfguiApp.fileChooser.getCurrentDirectory().getPath()+File.separator);
		MsfguiApp.showMessage(this, "Will now try running \n"
				+MsfguiApp.getPropertiesNode().get("commandPrefix")+"msfrpcd\n"
				+"and "+ MsfguiApp.getPropertiesNode().get("commandPrefix")+"ruby /msf3/msfrpcd\n"
				+ "when starting new daemon. Note: for the second to work on Windows,\n"
				+ "use something like Framework3\\bin not Framework3\\msf3");
	}//GEN-LAST:event_pathButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton cancelButton;
    private javax.swing.JButton connectButton;
    private javax.swing.JCheckBox disableDbButton;
    private javax.swing.JLabel disableDbLabel;
    private javax.swing.JTextField hostField;
    private javax.swing.JLabel hostLabel;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JLabel passwordLabel;
    private javax.swing.JButton pathButton;
    private javax.swing.JTextField portField;
    private javax.swing.JLabel portLabel;
    private javax.swing.JCheckBox sslBox;
    private javax.swing.JLabel sslLabel;
    private javax.swing.JButton startNewButton;
    private javax.swing.JLabel titleLabel;
    private javax.swing.JTextField usernameField;
    private javax.swing.JLabel usernameLabel;
    // End of variables declaration//GEN-END:variables
}
