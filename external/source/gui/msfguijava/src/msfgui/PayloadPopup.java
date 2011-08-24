package msfgui;

import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.ParallelGroup;
import javax.swing.GroupLayout.SequentialGroup;
import javax.swing.JFileChooser;

/**
 * Popup for generating payloads and starting handlers.
 * @author scriptjunkie
 */
public class PayloadPopup extends ModuleInfoWindow {
	
	/** Creates new form PayloadPopup */
	public PayloadPopup(String fullName, RpcConnection rpcConn, MainFrame frame) {
		moduleType = "payload";
		parentFrame = frame;
		initComponents();
		outputPathField.setText(MsfguiApp.getTempFolder()+File.separator+"msf.exe");
		this.rpcConn = rpcConn;
		requiredOpts = new ArrayList();
		optionalOpts = requiredOpts;
		advancedOpts = requiredOpts;
		this.fullName = fullName;
		showOptions(fullName);
		loadSavedSize();

		//get encoders
		try{
			Object[] encoders = ((List)((Map) rpcConn.execute("module.encoders")).get("modules")).toArray();
			int defaultEncoder = 0;
			for(int i = 0; i < encoders.length; i++)
				if(encoders[i].toString().equals("generic/none"))
					defaultEncoder = i;
			encoderCombo.setModel(new DefaultComboBoxModel(encoders));
			encoderCombo.setSelectedIndex(defaultEncoder);
		}catch(MsfException xre){
		}
	}

	private void doRun(boolean console) {
		Map hash = getOptions(mainPanel);
		hash.put("PAYLOAD", fullName);
		hash.put("TARGET", "0");
		run("exploit", "multi/handler", hash, console);
	}

	/** Resets group layout displaying appropriate elements */
	private void resetLayout(){
		boolean saving = saveButton.isSelected();
		outputScrollPane.setVisible(!saving);
		archField.setVisible(saving);
		archLabel.setVisible(saving);
		choosePathButton.setVisible(saving);
		encoderCombo.setVisible(saving);
		encoderLabel.setVisible(saving);
		outputCombo.setVisible(saving);
		outputLabel.setVisible(saving);
		outputPathField.setVisible(saving);
		outputPathLabel.setVisible(saving);
		templateButton.setVisible(saving);
		templateField.setVisible(saving);
		templateLabel.setVisible(saving);
		templateWorkingCheck.setVisible(saving);
		timesField.setVisible(saving);
		timesLabel.setVisible(saving);
		addCodeButton.setVisible(saving);
		addCodeLabel.setVisible(saving);
		addCodeField.setVisible(saving);

		GroupLayout mainPanelLayout = (GroupLayout)mainPanel.getLayout();
		//HORIZONTAL GROUPING
		ParallelGroup labelGroup = mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING);
		//make label group
		for(int i = 0; i < optionalOpts.size(); i+= 2)
			labelGroup = labelGroup.addComponent((Component)optionalOpts.get(i), javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE);
		//make text box group
		ParallelGroup textBoxGroup = mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING);
		for(int i = 1; i < optionalOpts.size(); i+= 2)
			textBoxGroup = textBoxGroup.addComponent((Component)optionalOpts.get(i));
		//put it together
		mainPanelLayout.setHorizontalGroup(
		mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
			.addGroup(mainPanelLayout.createSequentialGroup()
			.addContainerGap()
			.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
					.addComponent(titleLabel)
					.addComponent(descriptionBox)
					.addComponent(authorsLabel)
					.addComponent(licenseLabel)
					.addComponent(versionLabel)
					.addGroup(mainPanelLayout.createSequentialGroup()
							.addGroup(labelGroup)
							.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
							.addGroup(textBoxGroup)
							.addContainerGap())
					.addGroup(mainPanelLayout.createSequentialGroup()
						.addComponent(generateButton)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(displayButton)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(saveButton)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addComponent(handleButton)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(handleConsoleButton))
					.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
						.addComponent(outputScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 40, Short.MAX_VALUE)
						.addContainerGap())
					.addGroup(mainPanelLayout.createSequentialGroup()
						.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
							.addComponent(encoderLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(outputLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(archLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(timesLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(outputPathLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(templateLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(addCodeLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
							.addComponent(encoderCombo, 0, 188, Short.MAX_VALUE)
							.addComponent(outputCombo, 0, 188, Short.MAX_VALUE)
							.addComponent(archField, javax.swing.GroupLayout.DEFAULT_SIZE, 188, Short.MAX_VALUE)
							.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
								.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
									.addComponent(templateField, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)
									.addComponent(outputPathField, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)
									.addComponent(addCodeField, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
									.addComponent(templateButton)
									.addComponent(choosePathButton)
									.addComponent(addCodeButton)))
							.addComponent(timesField, javax.swing.GroupLayout.DEFAULT_SIZE, 188, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(templateWorkingCheck)))
						.addContainerGap()));
					
		//VERTICAL GROUPING
		SequentialGroup groupie = mainPanelLayout.createSequentialGroup().
				addComponent(titleLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(descriptionBox).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(authorsLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(licenseLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(versionLabel);
		for(int i = 0; i < optionalOpts.size(); i+=2){
			groupie = groupie.addGroup(mainPanelLayout.createParallelGroup(
					javax.swing.GroupLayout.Alignment.BASELINE)
				.addComponent((Component)optionalOpts.get(i)) //LABEL
				.addComponent((Component)optionalOpts.get(i+1), //TEXT BOX
					javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
					javax.swing.GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
		}
		groupie = groupie
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(generateButton)
					.addComponent(displayButton)
					.addComponent(saveButton)
					.addComponent(handleButton)
					.addComponent(handleConsoleButton))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(outputScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE);
		if(saving)
			groupie = groupie.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(outputPathLabel)
					.addComponent(outputPathField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
					.addComponent(choosePathButton))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(encoderLabel)
					.addComponent(encoderCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(outputLabel)
					.addComponent(outputCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(timesLabel)
					.addComponent(timesField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(archLabel)
					.addComponent(archField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(templateLabel)
					.addComponent(templateField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
					.addComponent(templateButton)
					.addComponent(templateWorkingCheck))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(addCodeLabel)
					.addComponent(addCodeField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
					.addComponent(addCodeButton));
		groupie = groupie.addContainerGap();
		mainPanelLayout.setVerticalGroup(mainPanelLayout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addGroup(groupie));
	}
   /** Displays payload info and options. */
	private void showOptions(String fullName) {
		Map info = showBasicInfo(rpcConn, fullName);
		showOptions(mainPanel, null);
		resetLayout();
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
        jScrollPane1 = new javax.swing.JScrollPane();
        mainPanel = new javax.swing.JPanel();
        timesField = new javax.swing.JTextField();
        encoderCombo = new javax.swing.JComboBox();
        outputCombo = new javax.swing.JComboBox();
        templateButton = new javax.swing.JButton();
        templateWorkingCheck = new javax.swing.JCheckBox();
        archLabel = new javax.swing.JLabel();
        outputLabel = new javax.swing.JLabel();
        timesLabel = new javax.swing.JLabel();
        archField = new javax.swing.JTextField();
        descriptionBox = new javax.swing.JLabel();
        encoderLabel = new javax.swing.JLabel();
        generateButton = new javax.swing.JButton();
        outputScrollPane = new javax.swing.JScrollPane();
        outputPane = new javax.swing.JTextArea();
        displayButton = new javax.swing.JRadioButton();
        saveButton = new javax.swing.JRadioButton();
        outputPathLabel = new javax.swing.JLabel();
        outputPathField = new javax.swing.JTextField();
        choosePathButton = new javax.swing.JButton();
        templateLabel = new javax.swing.JLabel();
        templateField = new javax.swing.JTextField();
        handleButton = new javax.swing.JButton();
        handleConsoleButton = new javax.swing.JButton();
        addCodeLabel = new javax.swing.JLabel();
        addCodeField = new javax.swing.JTextField();
        addCodeButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setName("Form"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        mainPanel.setName("mainPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(PayloadPopup.class);
        timesField.setText(resourceMap.getString("timesField.text")); // NOI18N
        timesField.setName("timesField"); // NOI18N

        encoderCombo.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        encoderCombo.setName("encoderCombo"); // NOI18N

        outputCombo.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "c", "elf", "exe", "jar", "java", "js_le", "js_be", "perl", "raw", "ruby", "vba", "vbs", "loop-vbs", "asp", "war", "macho" }));
        outputCombo.setName("outputCombo"); // NOI18N

        templateButton.setText(resourceMap.getString("templateButton.text")); // NOI18N
        templateButton.setName("templateButton"); // NOI18N
        templateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                templateButtonActionPerformed(evt);
            }
        });

        templateWorkingCheck.setText(resourceMap.getString("templateWorkingCheck.text")); // NOI18N
        templateWorkingCheck.setName("templateWorkingCheck"); // NOI18N

        archLabel.setText(resourceMap.getString("archLabel.text")); // NOI18N
        archLabel.setName("archLabel"); // NOI18N

        outputLabel.setText(resourceMap.getString("outputLabel.text")); // NOI18N
        outputLabel.setName("outputLabel"); // NOI18N

        timesLabel.setText(resourceMap.getString("timesLabel.text")); // NOI18N
        timesLabel.setName("timesLabel"); // NOI18N

        archField.setText(resourceMap.getString("archField.text")); // NOI18N
        archField.setName("archField"); // NOI18N

        descriptionBox.setText(resourceMap.getString("descriptionBox.text")); // NOI18N
        descriptionBox.setName("descriptionBox"); // NOI18N

        encoderLabel.setText(resourceMap.getString("encoderLabel.text")); // NOI18N
        encoderLabel.setName("encoderLabel"); // NOI18N

        generateButton.setText(resourceMap.getString("generateButton.text")); // NOI18N
        generateButton.setName("generateButton"); // NOI18N
        generateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateButtonActionPerformed(evt);
            }
        });

        outputScrollPane.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        outputScrollPane.setName("outputScrollPane"); // NOI18N

        outputPane.setColumns(20);
        outputPane.setEditable(false);
        outputPane.setLineWrap(true);
        outputPane.setName("outputPane"); // NOI18N
        outputScrollPane.setViewportView(outputPane);

        buttonGroup1.add(displayButton);
        displayButton.setSelected(true);
        displayButton.setText(resourceMap.getString("displayButton.text")); // NOI18N
        displayButton.setName("displayButton"); // NOI18N
        displayButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                displayButtonActionPerformed(evt);
            }
        });

        buttonGroup1.add(saveButton);
        saveButton.setText(resourceMap.getString("saveButton.text")); // NOI18N
        saveButton.setName("saveButton"); // NOI18N
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });

        outputPathLabel.setText(resourceMap.getString("outputPathLabel.text")); // NOI18N
        outputPathLabel.setName("outputPathLabel"); // NOI18N

        outputPathField.setText(resourceMap.getString("outputPathField.text")); // NOI18N
        outputPathField.setName("outputPathField"); // NOI18N

        choosePathButton.setText(resourceMap.getString("choosePathButton.text")); // NOI18N
        choosePathButton.setName("choosePathButton"); // NOI18N
        choosePathButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                choosePathButtonActionPerformed(evt);
            }
        });

        templateLabel.setText(resourceMap.getString("templateLabel.text")); // NOI18N
        templateLabel.setName("templateLabel"); // NOI18N

        templateField.setName("templateField"); // NOI18N

        handleButton.setText(resourceMap.getString("handleButton.text")); // NOI18N
        handleButton.setName("handleButton"); // NOI18N
        handleButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                handleButtonActionPerformed(evt);
            }
        });

        handleConsoleButton.setText(resourceMap.getString("handleConsoleButton.text")); // NOI18N
        handleConsoleButton.setName("handleConsoleButton"); // NOI18N
        handleConsoleButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                handleConsoleButtonActionPerformed(evt);
            }
        });

        addCodeLabel.setText(resourceMap.getString("addCodeLabel.text")); // NOI18N
        addCodeLabel.setName("addCodeLabel"); // NOI18N

        addCodeField.setText(resourceMap.getString("addCodeField.text")); // NOI18N
        addCodeField.setName("addCodeField"); // NOI18N

        addCodeButton.setText(resourceMap.getString("addCodeButton.text")); // NOI18N
        addCodeButton.setName("addCodeButton"); // NOI18N
        addCodeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addCodeButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(descriptionBox, javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, mainPanelLayout.createSequentialGroup()
                                .addComponent(generateButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(displayButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(saveButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(handleButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(handleConsoleButton)))
                        .addGap(500, 500, 500))
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(mainPanelLayout.createSequentialGroup()
                                .addComponent(outputScrollPane, javax.swing.GroupLayout.PREFERRED_SIZE, 691, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(mainPanelLayout.createSequentialGroup()
                                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(encoderLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(outputLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(timesLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(outputPathLabel)
                                        .addComponent(addCodeLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                    .addComponent(templateLabel)
                                    .addComponent(archLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(archField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 310, Short.MAX_VALUE)
                                    .addComponent(timesField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 310, Short.MAX_VALUE)
                                    .addComponent(outputCombo, javax.swing.GroupLayout.Alignment.LEADING, 0, 310, Short.MAX_VALUE)
                                    .addComponent(encoderCombo, javax.swing.GroupLayout.Alignment.LEADING, 0, 310, Short.MAX_VALUE)
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, mainPanelLayout.createSequentialGroup()
                                        .addComponent(outputPathField, javax.swing.GroupLayout.PREFERRED_SIZE, 213, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(choosePathButton, javax.swing.GroupLayout.PREFERRED_SIZE, 91, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(mainPanelLayout.createSequentialGroup()
                                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                            .addComponent(addCodeField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 217, Short.MAX_VALUE)
                                            .addComponent(templateField, javax.swing.GroupLayout.DEFAULT_SIZE, 217, Short.MAX_VALUE))
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addComponent(addCodeButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(templateButton, javax.swing.GroupLayout.DEFAULT_SIZE, 87, Short.MAX_VALUE))))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(templateWorkingCheck)))
                        .addGap(349, 349, 349))))
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addGap(54, 54, 54)
                .addComponent(descriptionBox)
                .addGap(78, 78, 78)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(generateButton)
                    .addComponent(displayButton)
                    .addComponent(saveButton)
                    .addComponent(handleButton)
                    .addComponent(handleConsoleButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(outputScrollPane)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(outputPathLabel)
                    .addComponent(outputPathField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(choosePathButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encoderLabel)
                    .addComponent(encoderCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(outputLabel)
                    .addComponent(outputCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(timesLabel)
                    .addComponent(timesField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(archLabel)
                    .addComponent(archField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(templateLabel)
                    .addComponent(templateField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(templateButton)
                    .addComponent(templateWorkingCheck))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(addCodeLabel)
                    .addComponent(addCodeField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(addCodeButton))
                .addContainerGap())
        );

        jScrollPane1.setViewportView(mainPanel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 795, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

	private void generateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateButtonActionPerformed
		try {
			HashMap hash = getOptions(mainPanel);
			if(outputCombo.getSelectedItem().toString().equals("jar"))
				hash.put("Format", "jar");
			hash.put("Encoder", "generic/none");
			Map data = (Map) rpcConn.execute("module.execute", "payload", fullName,hash);
			//Basic info
			byte[] buffer;
			String rawHex;
			if(rpcConn.type.equals("msg")){
				buffer = (byte[])data.get("payload");
			}else{
				rawHex = data.get("payload").toString();
				buffer = new byte[rawHex.length() / 2];
				for (int i = 0; i < rawHex.length(); i += 2)
					buffer[i/2] = (byte)Integer.parseInt(rawHex.substring(i, i + 2),16);
			}

			if(saveButton.isSelected()){ //Encode and output
				hash.put("format", outputCombo.getSelectedItem().toString());
				if(timesField.getText().length() > 0)
					hash.put("ecount", timesField.getText());
				if(archField.getText().length() > 0)
					hash.put("arch", archField.getText());
				if(addCodeField.getText().length() > 0)
					hash.put("addshellcode", addCodeField.getText());
				if(templateField.getText().length() > 0){
					hash.put("altexe", templateField.getText());
					if(templateWorkingCheck.isSelected())
						hash.put("inject", true);
				}
				if(!outputCombo.getSelectedItem().toString().equals("jar")){ //jars don't get encoded
					Map encoded = (Map) rpcConn.execute("module.encode", buffer,
							encoderCombo.getSelectedItem().toString(),hash);
					if(rpcConn.type.equals("msg"))
						buffer = (byte[])encoded.get("encoded");
					else
						buffer = Base64.decode(encoded.get("encoded").toString());
				}
				FileOutputStream fout = new FileOutputStream(outputPathField.getText());
				fout.write(buffer);
				fout.close();
				return;
			}

			outputPane.setText("Payload "+fullName+" "+hash+" "+buffer.length+" bytes.");
			boolean isPlain = true;
			StringBuilder plain = new StringBuilder("");
			for(int i = 0; i < buffer.length; i++){
				if (!Character.isISOControl(buffer[i]))// or check isLetterOrDigit isWhitespace or " , . (){}-_+=<>.,?/'"; etc.
					plain.append((char)buffer[i]);
				else
					isPlain = false;
			}
			if(isPlain)
				outputPane.append("\n\nplain text\n"+plain);
			StringBuilder rubyHex = new StringBuilder("\"");
			for(int i = 0; i < buffer.length; i += 10){
				for(int j = 0; j < 10 && i + j < buffer.length; j++){
					rubyHex.append("\\x");
					rubyHex.append(Integer.toString((buffer[i+j] & 0xF0)/16,16));
					rubyHex.append(Integer.toString(buffer[i+j] & 0x0F,16));
				}
				rubyHex.append("\"");
				if(i + 10 < buffer.length)
					rubyHex.append("+\n\"");
			}
			outputPane.append("\n\nruby\n"+rubyHex);
		} catch (MsfException ex) {
			MsfguiApp.showMessage(this, ex);
		} catch (IOException ex) {
			MsfguiApp.showMessage(this, ex);
		}
	}//GEN-LAST:event_generateButtonActionPerformed

	private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed
		resetLayout();
	}//GEN-LAST:event_saveButtonActionPerformed

	private void displayButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_displayButtonActionPerformed
		resetLayout();
	}//GEN-LAST:event_displayButtonActionPerformed

	private void choosePathButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_choosePathButtonActionPerformed
		if(MsfguiApp.fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION)
			outputPathField.setText(MsfguiApp.fileChooser.getSelectedFile().getAbsolutePath());
	}//GEN-LAST:event_choosePathButtonActionPerformed

	private void templateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_templateButtonActionPerformed
		if(MsfguiApp.fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
			templateField.setText(MsfguiApp.fileChooser.getSelectedFile().getAbsolutePath());
	}//GEN-LAST:event_templateButtonActionPerformed

	private void handleButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_handleButtonActionPerformed
		doRun(false);
	}//GEN-LAST:event_handleButtonActionPerformed

	private void handleConsoleButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_handleConsoleButtonActionPerformed
		doRun(true);
	}//GEN-LAST:event_handleConsoleButtonActionPerformed

	private void addCodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addCodeButtonActionPerformed
		if(MsfguiApp.fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
			addCodeField.setText(MsfguiApp.fileChooser.getSelectedFile().getAbsolutePath());
	}//GEN-LAST:event_addCodeButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addCodeButton;
    private javax.swing.JTextField addCodeField;
    private javax.swing.JLabel addCodeLabel;
    private javax.swing.JTextField archField;
    private javax.swing.JLabel archLabel;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton choosePathButton;
    public javax.swing.JLabel descriptionBox;
    private javax.swing.JRadioButton displayButton;
    private javax.swing.JComboBox encoderCombo;
    private javax.swing.JLabel encoderLabel;
    private javax.swing.JButton generateButton;
    private javax.swing.JButton handleButton;
    private javax.swing.JButton handleConsoleButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JComboBox outputCombo;
    private javax.swing.JLabel outputLabel;
    private javax.swing.JTextArea outputPane;
    private javax.swing.JTextField outputPathField;
    private javax.swing.JLabel outputPathLabel;
    private javax.swing.JScrollPane outputScrollPane;
    private javax.swing.JRadioButton saveButton;
    private javax.swing.JButton templateButton;
    private javax.swing.JTextField templateField;
    private javax.swing.JLabel templateLabel;
    private javax.swing.JCheckBox templateWorkingCheck;
    private javax.swing.JTextField timesField;
    private javax.swing.JLabel timesLabel;
    // End of variables declaration//GEN-END:variables

}
