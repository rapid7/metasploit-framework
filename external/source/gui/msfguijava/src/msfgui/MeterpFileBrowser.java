package msfgui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.locks.ReentrantLock;
import javax.swing.JOptionPane;
import javax.swing.Icon;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.Timer;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

/**
 * Provides a file browser for meterpreter sessions. Synchronizes with other windows.
 * @author scriptjunkie
 */
public class MeterpFileBrowser extends MsfFrame {
	protected Map session, sessionPopupMap;
	protected final RpcConnection rpcConn;
	protected ReentrantLock lock;
	protected Map files;
	protected List fileVector;
	protected Timer readTimer = null;
	protected final Icon folderIcon, fileIcon;
	protected JFileChooser fchooser;
	protected JPopupMenu popupMenu;
	protected final DefaultTableModel model;
	protected JPanel interactPane;

	/** Shows file interaction window for a session, creating one if necessary */
	static void showBrowser(RpcConnection rpcConn, Map session, Map sessionWindowMap) {
		Object browserWindow = sessionWindowMap.get(session.get("id")+"fileBrowser");
		if(browserWindow == null){
			browserWindow = new MeterpFileBrowser(rpcConn,session,sessionWindowMap).mainPanel;
			sessionWindowMap.put(session.get("id")+"fileBrowser",browserWindow);
		}
		DraggableTabbedPane.show((Component)browserWindow);
	}

	/** Creates a new window for interacting with filesystem */
	public MeterpFileBrowser(final RpcConnection rpcConn, final Map session, Map sessionPopupMap) {
		super("Meterpreter remote file browsing");
		this.rpcConn = rpcConn;
		this.session = session;
		this.interactPane = ((JPanel)sessionPopupMap.get(session.get("id")+"console"));
		this.lock = (ReentrantLock) sessionPopupMap.get(session.get("id")+"lock");
		files = new HashMap();
		fileVector = new Vector(100);
		initComponents();
		loadSavedSize();
		model = new DefaultTableModel(){
			public boolean isCellEditable(int row, int col){
				return false;
			}
            public Class getColumnClass(int columnIndex) {
                try{
					return getValueAt(0, columnIndex).getClass();
				}catch(ArrayIndexOutOfBoundsException aioobex){
				}catch(NullPointerException aioobex){
				}
				return java.lang.String.class;
            }
		};
		tabbedPane.setTitleAt(0, "Session "+session.get("id")+" file browser");
		mainTable.setModel(model);
		mainTable.setShowHorizontalLines(false);
		mainTable.setShowVerticalLines(false);
		fchooser = new JFileChooser();
		
		final FileSystemView view = FileSystemView.getFileSystemView();
		folderIcon = view.getSystemIcon(view.getDefaultDirectory());
		File tempFile = null;
		Icon tempIcon;
		try{
			tempFile = File.createTempFile("temp", ".txt");
			tempIcon = view.getSystemIcon(tempFile);
			tempFile.delete();
		} catch (IOException iox){
			tempIcon = null;
			MsfguiApp.showMessage(null, "Cannot create temp file. Weird.");
		}
		fileIcon = tempIcon;
		tempFile.delete();
		mainTable.setDefaultRenderer(Object.class,new DefaultTableCellRenderer(){
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col){
				// Get the renderer component from parent class
				JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
				if(!mainTable.getColumnName(col).equals("Name")){
					label.setIcon(null);
					return label;
				}
				if(files.get(value) != null && files.get(value).equals("dir")){
					label.setIcon(folderIcon);
					return label;
				}
				try{
					File tempFile = File.createTempFile("temp",value.toString());
					label.setIcon(view.getSystemIcon(tempFile));
					tempFile.delete();
				} catch (IOException iox){
					label.setIcon(fileIcon);
				}
				return label;
			}
		});
		mainTable.setAutoCreateRowSorter(true);
		fchooser.setMultiSelectionEnabled(false);
		popupMenu = new JPopupMenu();
		JMenuItem men = new JMenuItem("Delete");
		men.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				delete();
			}
		});
		popupMenu.add(men);
		men = new JMenuItem("Download");
		men.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				download();
			}
		});
		popupMenu.add(men);
		setupPopupMenu( rpcConn, session);
		//See if we need to move our tab
		Map props = MsfguiApp.getPropertiesNode();
		if(!props.get("tabWindowPreference").equals("window")){
			((DraggableTabbedPane)tabbedPane).moveTabTo(0, DraggableTabbedPane.getTabPane(interactPane));
			DraggableTabbedPane.show(mainPanel);
		}
		// Some exploits open in C:\Windows\system32. Too many files in there! Try to move to C:\ which should be more manageable
		executeCommand("cd \"C:\\\\\"");
		getFiles();
	}

	/** Calls meterpreter_write with the session ID and cmd. */
	private void executeCommand(String cmd){
		try{
			rpcConn.execute("session.meterpreter_run_single", session.get("id"), cmd);
		} catch (Exception ex) {
			MsfguiApp.showMessage(this, ex);
		}
	}
	/** Handles click events, like popup menu and double-click navigation */
	private void setupPopupMenu(final RpcConnection rpcConn, final Map session) {
		mainTable.addMouseListener(new PopupMouseListener() {
			public void doubleClicked(MouseEvent e) {
				//show interaction window on double-click
				int indx = mainTable.getSelectedRow();
				if (indx == -1) 
					return;
				String clickedFile = mainTable.getValueAt(indx, 0).toString();
				if (files.get(clickedFile).equals("dir")) {
					executeCommand("cd " + MsfguiApp.escapeBackslashes(clickedFile));
					getFiles();
				} else {
					download();
				}
			}

			public void showPopup(MouseEvent e) {
				int indx = mainTable.getSelectedRow();
				if (indx == -1)
					return;
				popupMenu.show(mainTable, e.getX(), e.getY());
			}
		});
	}

	/** Deletes selected file */
	protected void delete() {
		int[] indxs = mainTable.getSelectedRows();
		for(int indx : indxs){
			String clickedFile = mainTable.getValueAt(indx, 0).toString();
			if (files.get(clickedFile).equals("dir"))
				executeCommand("rmdir " + MsfguiApp.escapeBackslashes(clickedFile));
			else
				executeCommand("rm " + MsfguiApp.escapeBackslashes(clickedFile));
		}
		getFiles();
	}

	/** Retrieves list of files. */
	private void getFiles() {
		//Set up locking so the console doesn't eat our output
		lock.lock();

		while(model.getRowCount() > 0)
			model.removeRow(0);
		executeCommand("ls");
		if(readTimer != null && readTimer.isRunning())
			return;
		readTimer = new Timer(300, new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					Map received = (Map) rpcConn.execute("session.meterpreter_read", session.get("id"));
					byte[] decodedBytes = RpcConnection.getData(received);
					if (decodedBytes.length == 0)
						return;
					String[] lines = new String(decodedBytes).split("\n");
					String headerRow = null;
					String headerNames = null;
					for(String line : lines){
						line = line.trim();
						if(line.startsWith("Listing")){
							addressField.setText(line.substring(line.indexOf(' ')+1));
						}else if(line.startsWith("Mode")){
							headerNames = line;
						}else if(line.startsWith("-")){
							headerRow = line;
							model.setColumnIdentifiers(TableHelper.fill(headerNames,line));
							while(model.getRowCount() > 0)
								model.removeRow(0);
						}
						if(line.length() == 0 || line.charAt(0) < '0' || line.charAt(0) > '9')
							continue;
						String filename = line.substring(getEndOfWhitespaceBlock(line, 6));
						fileVector.add(filename);
						int indx = getEndOfWhitespaceBlock(line, 2);
						files.put(filename,line.substring(indx,indx+3));
						model.addRow(TableHelper.fill(line,headerRow));
					}
					stop();
					TableHelper.fitColumnWidths(model, mainTable);
					int nameColumn = -1;
					for(int i = 0; i < mainTable.getColumnCount(); i++)
						if(mainTable.getColumnName(i).equals("Name"))
							nameColumn = i;
					if(nameColumn != -1)
						mainTable.moveColumn(nameColumn, 0);
				} catch (Exception ex) {
					ex.printStackTrace();
					if(ex.getMessage().toLowerCase().contains("unknown session"))
						stop();
					MsfguiApp.showMessage(null, ex);
				}
			}

			/** Stops read timer, and releases lock */
			private void stop(){
				readTimer.stop();
				lock.unlock();
			}

			/** Helps parsing responses. */
			private int getEndOfWhitespaceBlock(String line, int num) {
				int whiteSpaces = 0;
				int indx = 0;
				while (whiteSpaces < num) {
					if (Character.isWhitespace(line.charAt(indx)) && !Character.isWhitespace(line.charAt(indx + 1))) 
						whiteSpaces++;
					indx++;
				}
				return indx;
			}
		});
		readTimer.start();
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
        mainPanel = new javax.swing.JPanel();
        upButton = new javax.swing.JButton();
        pwdLabel = new javax.swing.JLabel();
        addressField = new javax.swing.JTextField();
        goButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        mainTable = new javax.swing.JTable();
        refreshButton = new javax.swing.JButton();
        downloadButton = new javax.swing.JButton();
        deleteButton = new javax.swing.JButton();
        uploadButton = new javax.swing.JButton();
        dirButton = new javax.swing.JButton();
        recSearchDownloadButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        tabbedPane.setName("tabbedPane"); // NOI18N

        mainPanel.setName("mainPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(MeterpFileBrowser.class);
        upButton.setText(resourceMap.getString("upButton.text")); // NOI18N
        upButton.setName("upButton"); // NOI18N
        upButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                upButtonActionPerformed(evt);
            }
        });

        pwdLabel.setText(resourceMap.getString("pwdLabel.text")); // NOI18N
        pwdLabel.setName("pwdLabel"); // NOI18N

        addressField.setText(resourceMap.getString("addressField.text")); // NOI18N
        addressField.setName("addressField"); // NOI18N
        addressField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addressFieldActionPerformed(evt);
            }
        });

        goButton.setText(resourceMap.getString("goButton.text")); // NOI18N
        goButton.setName("goButton"); // NOI18N
        goButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                goButtonActionPerformed(evt);
            }
        });

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        mainTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        mainTable.setName("mainTable"); // NOI18N
        jScrollPane1.setViewportView(mainTable);

        refreshButton.setText(resourceMap.getString("refreshButton.text")); // NOI18N
        refreshButton.setName("refreshButton"); // NOI18N
        refreshButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshButtonActionPerformed(evt);
            }
        });

        downloadButton.setText(resourceMap.getString("downloadButton.text")); // NOI18N
        downloadButton.setName("downloadButton"); // NOI18N
        downloadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                downloadButtonActionPerformed(evt);
            }
        });

        deleteButton.setText(resourceMap.getString("deleteButton.text")); // NOI18N
        deleteButton.setName("deleteButton"); // NOI18N
        deleteButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteButtonActionPerformed(evt);
            }
        });

        uploadButton.setText(resourceMap.getString("uploadButton.text")); // NOI18N
        uploadButton.setName("uploadButton"); // NOI18N
        uploadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                uploadButtonActionPerformed(evt);
            }
        });

        dirButton.setText(resourceMap.getString("dirButton.text")); // NOI18N
        dirButton.setName("dirButton"); // NOI18N
        dirButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dirButtonActionPerformed(evt);
            }
        });

        recSearchDownloadButton.setText(resourceMap.getString("recSearchDownloadButton.text")); // NOI18N
        recSearchDownloadButton.setName("recSearchDownloadButton"); // NOI18N
        recSearchDownloadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                recSearchDownloadButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 889, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, mainPanelLayout.createSequentialGroup()
                        .addComponent(upButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pwdLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(addressField, javax.swing.GroupLayout.DEFAULT_SIZE, 725, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(goButton))
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(refreshButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 254, Short.MAX_VALUE)
                        .addComponent(recSearchDownloadButton)
                        .addGap(18, 18, 18)
                        .addComponent(dirButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(uploadButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(deleteButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(downloadButton)))
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(upButton)
                    .addComponent(pwdLabel)
                    .addComponent(addressField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(goButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 427, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(refreshButton)
                    .addComponent(downloadButton)
                    .addComponent(deleteButton)
                    .addComponent(uploadButton)
                    .addComponent(dirButton)
                    .addComponent(recSearchDownloadButton))
                .addContainerGap())
        );

        tabbedPane.addTab("tab1", mainPanel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 925, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabbedPane, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 567, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

	private void downloadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_downloadButtonActionPerformed
		download();
	}//GEN-LAST:event_downloadButtonActionPerformed

	private void uploadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_uploadButtonActionPerformed
		fchooser.setDialogTitle("Select file to upload");
		fchooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		if(fchooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
			return;
		executeCommand("lcd "+MsfguiApp.escapeBackslashes(fchooser.getSelectedFile().getParent()));
		executeCommand("upload " + MsfguiApp.escapeBackslashes(fchooser.getSelectedFile().getName()));
		getFiles();
	}//GEN-LAST:event_uploadButtonActionPerformed

	private void deleteButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteButtonActionPerformed
		delete();
	}//GEN-LAST:event_deleteButtonActionPerformed

	private void dirButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dirButtonActionPerformed
		String newDir = JOptionPane.showInputDialog(this,"New directory name","Choose Directory Name",JOptionPane.QUESTION_MESSAGE);
		if(newDir == null)
			return;
		executeCommand("mkdir " + MsfguiApp.escapeBackslashes(newDir));
		getFiles();
	}//GEN-LAST:event_dirButtonActionPerformed

	private void refreshButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshButtonActionPerformed
		getFiles();
	}//GEN-LAST:event_refreshButtonActionPerformed

	private void upButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_upButtonActionPerformed
		executeCommand("cd ..");
		getFiles();
	}//GEN-LAST:event_upButtonActionPerformed

	private void recSearchDownloadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_recSearchDownloadButtonActionPerformed
		try{
			String currentDir = addressField.getText();
			rpcConn.execute("session.meterpreter_script", session.get("id"),
				new SearchDwldOptionsDialog(this, currentDir).toString());
			setVisible(false);
			dispose();

			DraggableTabbedPane.show(interactPane);
		}catch (NullPointerException nex){//cancelled
		}catch (Exception ex){
			MsfguiApp.showMessage(null, ex);
		}
	}//GEN-LAST:event_recSearchDownloadButtonActionPerformed

	//Applies given directory change
	private void applyDirectoryChange(){
		if(addressField.getText().equals("/"))
			executeCommand("cd /../"); //Weird annonying bug. "cd /" doesn't work
		else
			executeCommand("cd " + MsfguiApp.escapeBackslashes(addressField.getText()));
		getFiles();
	}
	private void goButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_goButtonActionPerformed
		applyDirectoryChange();
	}//GEN-LAST:event_goButtonActionPerformed

	private void addressFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addressFieldActionPerformed
		applyDirectoryChange();
	}//GEN-LAST:event_addressFieldActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField addressField;
    private javax.swing.JButton deleteButton;
    private javax.swing.JButton dirButton;
    private javax.swing.JButton downloadButton;
    private javax.swing.JButton goButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JTable mainTable;
    private javax.swing.JLabel pwdLabel;
    private javax.swing.JButton recSearchDownloadButton;
    private javax.swing.JButton refreshButton;
    private javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JButton upButton;
    private javax.swing.JButton uploadButton;
    // End of variables declaration//GEN-END:variables

	//Downloads selected files, and folders recursively if desired.
	private void download() {
		fchooser.setDialogTitle("Select destination folder");
		fchooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		if(fchooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION)
			return;
		executeCommand("lcd " + MsfguiApp.escapeBackslashes(fchooser.getSelectedFile().toString()));
		for(int indx : mainTable.getSelectedRows())
			executeCommand("download " + MsfguiApp.escapeBackslashes(mainTable.getValueAt(indx, 0).toString()));
	}
}
