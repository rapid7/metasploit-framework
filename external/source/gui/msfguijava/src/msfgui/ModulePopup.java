package msfgui;

import java.awt.Component;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.ParallelGroup;
import javax.swing.GroupLayout.SequentialGroup;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JMenu;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

/**
 * Displays a window showing options for a module, and support for running the module.
 * @author scriptjunkie
 */
public class ModulePopup extends ModuleInfoWindow implements TreeSelectionListener{
	private JMenu recentMenu;
	private String payload;
	private String target;

	/** Creates new ModulePopup from recent run */
	public ModulePopup(RpcConnection rpcConn, Object[] args, MainFrame parentFrame) {
		this(args[1].toString(), rpcConn, args[0].toString(), parentFrame);
		Map opts = (Map)args[2];
		if(args[0].toString().equals("exploit")){
			//Set target
			if(opts.get("TARGET") != null)
				target = opts.get("TARGET").toString();
			else if (opts.containsKey("TARGET") && ((Map)opts.get("TARGET")).containsKey("default"))
				target = ((Map)opts.get("TARGET")).get("default").toString();
			else
				target = "0";
			for (Component comp : mainPanel.getComponents()){
				if(comp.getName().equals("targetButton"+target)){
					((JRadioButton)comp).setSelected(true);
					break;
				}
			}
			//Set payload
			showPayloads(rpcConn, fullName, target, opts.get("PAYLOAD").toString());
		}
		//Set options
		for(Component comp : mainPanel.getComponents()){
			Object optionVal = null;
			if(comp.getName() != null && comp.getName().startsWith("field"))
				optionVal = opts.get(comp.getName().substring("field".length()));
			if(optionVal == null)
				continue;
			if(comp instanceof JCheckBox)
				((JCheckBox)comp).setSelected(Boolean.TRUE.equals(optionVal));
			else if(comp instanceof JComboBox)
				((JComboBox)comp).setSelectedItem(optionVal);
			else if(comp instanceof JTextField)
				((JTextField)comp).setText(optionVal.toString());
		}
	}
	/** Creates new  ModulePopup */
	public ModulePopup(String fullName, RpcConnection rpcConn, String moduleType, MainFrame parentFrame) {
		this.parentFrame = parentFrame;
		this.recentMenu = parentFrame.recentMenu;
		initComponents();
		loadSavedSize();
		exploitButton.setText("Run "+moduleType);
		exploitButton1.setText("Run "+moduleType);
		exploitButton.setEnabled(false);
		exploitButton1.setEnabled(false);
		consoleRunButton.setEnabled(false);
		consoleRunButton1.setEnabled(false);
		this.moduleType = moduleType;
		requiredOpts = new ArrayList();
		optionalOpts = new ArrayList();
		advancedOpts = new ArrayList();
		this.fullName = fullName;
		setTitle(fullName);
		payload = "";
		this.rpcConn = rpcConn;
		showModuleInfo(rpcConn, fullName);
		if(moduleType.equals("exploit")){
			payloadTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
			//Listen for when the selection changes.
			payloadTree.addTreeSelectionListener(this);
			payloadTree.setToggleClickCount(1);
		} else {
			mainPanel.remove(payloadScrollPane);
			mainPanel.remove(targetsLabel);
		}
		descriptionBox.setFont(authorsLabel.getFont());
		descriptionBox.setBackground(authorsLabel.getBackground());
		mainScrollPane.getVerticalScrollBar().setUnitIncrement(40);
	}

	/** Sets selected payload to the official payload */
	public void valueChanged(TreeSelectionEvent e) {
		DefaultMutableTreeNode node = (DefaultMutableTreeNode)payloadTree.getLastSelectedPathComponent();
		if (node == null || !node.isLeaf())
			return;
		payload = node.getUserObject().toString();
		while(node.getParent() != node.getRoot()){
			node = (DefaultMutableTreeNode)node.getParent();
			payload = node.getUserObject() + "/" + payload;
		}
		showOptions();
	}

    /** Displays targetsMap on frame */
	private void showModuleInfo(final RpcConnection rpcConn, final String fullName) throws HeadlessException {
		try { //Get info
			Map info = showBasicInfo(rpcConn, fullName);
			if(moduleType.equals("exploit")){
				//Targets
				Map targetsMap = (Map) info.get("targets");
				if(targetsMap == null){
					MsfguiApp.showMessage(this, "No Targets. ??");
				}else{
					String defaultTarget="";
					if(info.get("default_target") != null)
						defaultTarget = info.get("default_target").toString();
					for (Object targetName : targetsMap.keySet()) {
						JRadioButton radio = new JRadioButton();
						buttonGroup.add(radio);
						radio.setText(targetsMap.get(targetName).toString()); // NOI18N
						radio.setName("targetButton" + targetName); // NOI18N
						radio.setActionCommand(targetName.toString());
						radio.addActionListener(new ActionListener(){
							public void actionPerformed(ActionEvent e) {
								target = buttonGroup.getSelection().getActionCommand();
								showPayloads(rpcConn,fullName,target);
							}
						});
						mainPanel.add(radio);
						if (targetName.equals(defaultTarget)) {
							radio.setSelected(true);
							showPayloads(rpcConn,fullName,targetName.toString());
						}
					}
				}
			} else { //AUXILIARY
				showOptions();
			}
		} catch (MsfException ex) {
			MsfguiApp.showMessage(rootPane, ex);
		}
		reGroup();
		updateSizes(mainPanel);
	}

   /** Creates payload menu. */
	private void showPayloads(RpcConnection rpcConn, String modName, String target) throws HeadlessException {
		showPayloads(rpcConn, modName, target, null);
	}
   /** Creates payload menu. */
	private void showPayloads(RpcConnection rpcConn, String modName, String target, String defaultPayload) throws HeadlessException {
		try { //Get info
			List mlist = (List)((Map)rpcConn.execute("module.target_compatible_payloads",
					modName,target)).get("payloads");
			//Ok. it worked. now replace the payload list

			DefaultTreeModel payloadModel = (DefaultTreeModel)payloadTree.getModel();
			DefaultMutableTreeNode top = (DefaultMutableTreeNode)(payloadModel.getRoot());
			int count = top.getChildCount();
			for(int i = count - 1; i >=0; i--){
				payloadModel.removeNodeFromParent((DefaultMutableTreeNode)top.getChildAt(i));
			}
			top.removeAllChildren();

			DefaultMutableTreeNode defaultPayloadNode = null;
			for (Object payloadFullName : mlist) {
				String[] names = payloadFullName.toString().split("/");
				DefaultMutableTreeNode currentNode = top;
				for (int i = 0; i < names.length; i++) {
					boolean found = false;
					for(int j = 0; j < currentNode.getChildCount(); j++){
						DefaultMutableTreeNode node = (DefaultMutableTreeNode)currentNode.getChildAt(j);
						if(node.getUserObject().toString().equals(names[i])){
							if (i < names.length - 1) 
								currentNode = node;
							found = true;
							break;
						}
					}
					if (found)
						continue;
					DefaultMutableTreeNode nod = new DefaultMutableTreeNode(names[i]);
					payloadModel.insertNodeInto(nod, currentNode, 0);
					if (i < names.length - 1) {
						payloadTree.scrollPathToVisible(new TreePath(nod.getPath()));
						currentNode = nod;
					}
					if(payloadFullName.equals(defaultPayload))
						defaultPayloadNode=nod;
				}//end for each subname
			}//end for each module
			if(defaultPayloadNode != null){
				payloadTree.scrollPathToVisible(new TreePath(defaultPayloadNode.getPath()));
				payloadTree.setSelectionPath(new TreePath(defaultPayloadNode.getPath()));
			}
			payloadTree.setRootVisible(false);
			payloadTree.revalidate();
		} catch (MsfException ex) {
			MsfguiApp.showMessage(rootPane, ex);
		}
	}

   /** Displays exploit and payload options. */
	private void showOptions() {
		exploitButton.setEnabled(true);
		exploitButton1.setEnabled(true);
		consoleRunButton.setEnabled(true);
		consoleRunButton1.setEnabled(true);
		showOptions(mainPanel, payload);
		reGroup();
	}

   /** Runs the exploit with given options and payload. Closes window if successful. */
	private void runModule(boolean console) {
		try{// Get options
			HashMap hash = getOptions(mainPanel);

			//Add exploit only options
			if(moduleType.equals("exploit")){
				if(payload.length() <= 0){
					MsfguiApp.showMessage(rootPane, "You must select a payload");
					return;
				}
				hash.put("PAYLOAD",payload.toString());
				target = buttonGroup.getSelection().getActionCommand();
				hash.put("TARGET",target);
			}
			//Actually run the module
			run(hash, console);

			//close out
			this.setVisible(false);
			this.dispose();
		} catch (MsfException ex) {
			MsfguiApp.showMessage(rootPane, ex);
		}
	}

   /** Reformats the view based on visible options and targetsMap. */
	private void reGroup(){
		GroupLayout mainPanelLayout = (GroupLayout)mainPanel.getLayout();
		ParallelGroup horizGroup = mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
			.addComponent(titleLabel)
			.addComponent(descriptionPane, javax.swing.GroupLayout.DEFAULT_SIZE, 300, Short.MAX_VALUE)
			.addComponent(authorsLabel)
			.addComponent(licenseLabel)
			.addComponent(versionLabel);
			//Exploit only stuff
			if(moduleType.equals("exploit")){
				horizGroup.addComponent(targetsLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
					.addComponent(payloadScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE);
			}
		horizGroup.addComponent(requiredLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
			.addComponent(optionalLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE);
		Enumeration targets = buttonGroup.getElements();
		while(targets.hasMoreElements())
			horizGroup = horizGroup.addComponent((JRadioButton)targets.nextElement());
		for(Object obj : requiredOpts)
			horizGroup = horizGroup.addComponent((Component) obj, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE);
		for(Object obj : optionalOpts)
			horizGroup = horizGroup.addComponent((Component) obj, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE);
		for(Object obj : advancedOpts)
			horizGroup = horizGroup.addComponent((Component) obj, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE);
		
		horizGroup = horizGroup.addGroup(mainPanelLayout.createSequentialGroup()
				.addComponent(exploitButton)
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(consoleRunButton))
			.addGroup(mainPanelLayout.createSequentialGroup()
				.addComponent(exploitButton1)
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(consoleRunButton1));
		mainPanelLayout.setHorizontalGroup(mainPanelLayout.createSequentialGroup().addContainerGap()
				.addGroup(horizGroup).addContainerGap());

		SequentialGroup vGroup = mainPanelLayout.createSequentialGroup()
				.addContainerGap()
				.addComponent(titleLabel)
				.addComponent(descriptionPane, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
				.addComponent(authorsLabel)
				.addComponent(licenseLabel)
				.addComponent(versionLabel)
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
		//Exploit only stuff
		if(moduleType.equals("exploit")){
			vGroup.addComponent(targetsLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
			targets = buttonGroup.getElements();
			while(targets.hasMoreElements()){
				vGroup.addComponent((JRadioButton)targets.nextElement())
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
			}
			vGroup = vGroup.addComponent(payloadScrollPane, javax.swing.GroupLayout.PREFERRED_SIZE, 296, javax.swing.GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
		}
		addObjectsToVgroup(vGroup, requiredLabel, requiredOpts);
		vGroup.addGroup(mainPanelLayout.createParallelGroup()
			.addComponent(exploitButton1)
			.addComponent(consoleRunButton))
			.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
		addObjectsToVgroup(vGroup, optionalLabel, optionalOpts);
		addObjectsToVgroup(vGroup, advancedLabel, advancedOpts);
		vGroup = vGroup.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
			.addGroup(mainPanelLayout.createParallelGroup()
			.addComponent(exploitButton)
			.addComponent(consoleRunButton1))
			.addContainerGap();
		mainPanelLayout.setVerticalGroup(vGroup);
	}

	//helper for grouping
	private void addObjectsToVgroup(SequentialGroup vGroup, Component label, ArrayList opts) {
		vGroup = vGroup.addComponent(label, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE);
		for (Object obj : opts)
			vGroup.addComponent((Component) obj, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE);
	}

	/** This method is called from within the constructor to
	 * initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is
	 * always regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup = new javax.swing.ButtonGroup();
        mainScrollPane = new javax.swing.JScrollPane();
        mainPanel = new javax.swing.JPanel();
        targetsLabel = new javax.swing.JLabel();
        payloadScrollPane = new javax.swing.JScrollPane();
        payloadTree = new javax.swing.JTree();
        exploitButton = new javax.swing.JButton();
        requiredLabel = new javax.swing.JLabel();
        optionalLabel = new javax.swing.JLabel();
        descriptionPane = new javax.swing.JScrollPane();
        descriptionBox = new javax.swing.JEditorPane();
        advancedLabel = new javax.swing.JLabel();
        exploitButton1 = new javax.swing.JButton();
        consoleRunButton = new javax.swing.JButton();
        consoleRunButton1 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        mainScrollPane.setName("mainScrollPane"); // NOI18N

        mainPanel.setName("mainPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(ModulePopup.class);
        targetsLabel.setText(resourceMap.getString("targetsLabel.text")); // NOI18N
        targetsLabel.setName("targetsLabel"); // NOI18N

        payloadScrollPane.setName("payloadScrollPane"); // NOI18N

        javax.swing.tree.DefaultMutableTreeNode treeNode1 = new javax.swing.tree.DefaultMutableTreeNode("Payloads");
        payloadTree.setModel(new javax.swing.tree.DefaultTreeModel(treeNode1));
        payloadTree.setName("payloadTree"); // NOI18N
        payloadScrollPane.setViewportView(payloadTree);

        exploitButton.setText(resourceMap.getString("exploitButton.text")); // NOI18N
        exploitButton.setName("exploitButton"); // NOI18N
        exploitButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exploitButtonActionPerformed(evt);
            }
        });

        requiredLabel.setText(resourceMap.getString("requiredLabel.text")); // NOI18N
        requiredLabel.setName("requiredLabel"); // NOI18N

        optionalLabel.setText(resourceMap.getString("optionalLabel.text")); // NOI18N
        optionalLabel.setName("optionalLabel"); // NOI18N

        descriptionPane.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        descriptionPane.setName("descriptionPane"); // NOI18N

        descriptionBox.setContentType("text/html"); // NOI18N
        descriptionBox.setEditable(false);
        descriptionBox.setName("descriptionBox"); // NOI18N
        descriptionPane.setViewportView(descriptionBox);

        advancedLabel.setText(resourceMap.getString("advancedLabel.text")); // NOI18N
        advancedLabel.setName("advancedLabel"); // NOI18N

        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("msfgui/resources/ModulePopup"); // NOI18N
        exploitButton1.setText(bundle.getString("exploitButton.text")); // NOI18N
        exploitButton1.setName("exploitButton1"); // NOI18N
        exploitButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exploitButton1ActionPerformed(evt);
            }
        });

        consoleRunButton.setText(resourceMap.getString("consoleRunButton.text")); // NOI18N
        consoleRunButton.setName("consoleRunButton"); // NOI18N
        consoleRunButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                consoleRunButtonActionPerformed(evt);
            }
        });

        consoleRunButton1.setText(resourceMap.getString("consoleRunButton1.text")); // NOI18N
        consoleRunButton1.setName("consoleRunButton1"); // NOI18N
        consoleRunButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                consoleRunButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(descriptionPane, javax.swing.GroupLayout.DEFAULT_SIZE, 621, Short.MAX_VALUE)
                    .addComponent(targetsLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 431, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(payloadScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 621, Short.MAX_VALUE)
                    .addComponent(requiredLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(optionalLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(advancedLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(exploitButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(consoleRunButton))
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(exploitButton1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(consoleRunButton1)))
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addGap(36, 36, 36)
                .addComponent(descriptionPane, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(78, 78, 78)
                .addComponent(targetsLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(payloadScrollPane, javax.swing.GroupLayout.PREFERRED_SIZE, 296, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(requiredLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(optionalLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(advancedLabel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(exploitButton)
                    .addComponent(consoleRunButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(exploitButton1)
                    .addComponent(consoleRunButton1))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        mainScrollPane.setViewportView(mainPanel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(mainScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 663, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(mainScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 609, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

	private void exploitButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exploitButtonActionPerformed
		runModule(false);
	}//GEN-LAST:event_exploitButtonActionPerformed

	private void exploitButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exploitButton1ActionPerformed
		runModule(false);
	}//GEN-LAST:event_exploitButton1ActionPerformed

	private void consoleRunButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_consoleRunButtonActionPerformed
		runModule(true);
	}//GEN-LAST:event_consoleRunButtonActionPerformed

	private void consoleRunButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_consoleRunButton1ActionPerformed
		runModule(true);
	}//GEN-LAST:event_consoleRunButton1ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel advancedLabel;
    private javax.swing.ButtonGroup buttonGroup;
    private javax.swing.JButton consoleRunButton;
    private javax.swing.JButton consoleRunButton1;
    public javax.swing.JEditorPane descriptionBox;
    private javax.swing.JScrollPane descriptionPane;
    private javax.swing.JButton exploitButton;
    private javax.swing.JButton exploitButton1;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JScrollPane mainScrollPane;
    private javax.swing.JLabel optionalLabel;
    private javax.swing.JScrollPane payloadScrollPane;
    private javax.swing.JTree payloadTree;
    private javax.swing.JLabel requiredLabel;
    private javax.swing.JLabel targetsLabel;
    // End of variables declaration//GEN-END:variables
}
