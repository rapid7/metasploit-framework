/*
 * PayloadPopup.java
 *
 * Created on May 16, 2010, 12:17:16 AM
 */
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
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

/**
 *
 * @author scriptjunkie
 */
public class PayloadPopup extends MsfFrame {
	private RpcConnection rpcConn;
	private ArrayList elementVector;
	private String fullName;
	private MainFrame mainFrame;
	private Map options;
	
	/** Creates new form PayloadPopup */
	public PayloadPopup(String fullName, RpcConnection rpcConn, MainFrame frame) {
		mainFrame = frame;
		initComponents();
		outputPathField.setText(MsfguiApp.getTempFolder()+File.separator+"msf.exe");
		this.rpcConn = rpcConn;
		elementVector = new ArrayList();
		this.fullName = fullName;
		showOptions(fullName);

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
		setSize(800, 700);
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

		GroupLayout mainPanelLayout = (GroupLayout)mainPanel.getLayout();
		//HORIZONTAL GROUPING
		ParallelGroup labelGroup = mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING);
		//make label group
		for(int i = 0; i < elementVector.size(); i++)
			labelGroup = labelGroup.addComponent(((Component[])elementVector.get(i))[0], javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE);
		//make text box group
		ParallelGroup textBoxGroup = mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING);
		for(int i = 0; i < elementVector.size(); i++)
			textBoxGroup = textBoxGroup.addComponent(((Component[])elementVector.get(i))[1]);
		//put it together
		mainPanelLayout.setHorizontalGroup(
		mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
			.addGroup(mainPanelLayout.createSequentialGroup()
			.addContainerGap()
			.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
					.addComponent(titleLabel)
					.addComponent(descriptionLabel)
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
						.addComponent(handleButton))
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
							.addComponent(templateLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
							.addComponent(encoderCombo, 0, 188, Short.MAX_VALUE)
							.addComponent(outputCombo, 0, 188, Short.MAX_VALUE)
							.addComponent(archField, javax.swing.GroupLayout.DEFAULT_SIZE, 188, Short.MAX_VALUE)
							.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
								.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
									.addComponent(templateField, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)
									.addComponent(outputPathField, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
									.addComponent(templateButton)
									.addComponent(choosePathButton)))
							.addComponent(timesField, javax.swing.GroupLayout.DEFAULT_SIZE, 188, Short.MAX_VALUE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(templateWorkingCheck)))
						.addContainerGap()));
					
		//VERTICAL GROUPING
		SequentialGroup groupie = mainPanelLayout.createSequentialGroup().
				addComponent(titleLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(descriptionLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(authorsLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(licenseLabel).
				addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).
				addComponent(versionLabel);
		for(int i = 0; i < elementVector.size(); i++){
			groupie = groupie.addGroup(mainPanelLayout.createParallelGroup(
					javax.swing.GroupLayout.Alignment.BASELINE)
				.addComponent(((Component[])elementVector.get(i))[0]) //LABEL
				.addComponent(((Component[])elementVector.get(i))[1], //TEXT BOX
					javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
					javax.swing.GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
		}
		groupie = groupie
				.addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
					.addComponent(generateButton)
					.addComponent(displayButton)
					.addComponent(saveButton)
					.addComponent(handleButton))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
				.addComponent(outputScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
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
				.addContainerGap();
		mainPanelLayout.setVerticalGroup(mainPanelLayout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addGroup(groupie));
	}
   /** Displays payload info and options. */
	private void showOptions(String fullName) {
		try {
			Map info = (Map) rpcConn.execute("module.info", "payload", fullName);
			//Basic info
			setTitle(info.get("name") + " " + fullName);
			titleLabel.setText("<html><h2>"+info.get("name")+ "</h2></html>");
			//wrapLabelText(descriptionLabel, info.get("description").toString().replace("\n", " "));
			descriptionLabel.setText(info.get("description").toString().replace("\n", " "));
			if(info.get("license") instanceof String){
				licenseLabel.setText("<html><b>License:</b> "+ info.get("license")+"</html>");
			}else{
				List license = (List) info.get("license");
				StringBuilder licenseString = new StringBuilder();
				for(Object lic : license)
					licenseString.append(lic).append(" ");
				licenseLabel.setText("<html><b>License:</b> "+ licenseString+"</html>");
			}
			versionLabel.setText("<html><b>Version:</b> "+ info.get("version")+"</html>");
			//Authors
			List authors = (List) info.get("authors");
			StringBuilder authorLine = new StringBuilder();
			if (authors.size() > 0)
				authorLine.append(authors.get(0).toString());
			for (int i = 1; i < authors.size(); i++)
				authorLine.append(", ").append(authors.get(i));
			authorsLabel.setText("<html><b>Authors:</b> "+ authorLine.toString()+"</html>");

			//display options
			options = (Map) rpcConn.execute("module.options", "payload", fullName);
			for (Object optionName : options.keySet()) 
				addOption(optionName, (Map)options.get(optionName));
			resetLayout();
		} catch (MsfException ex) {
			JOptionPane.showMessageDialog(rootPane, ex);
		}
	}

	private void addOption(Object optionName, Map option) {
		JLabel lab = new JLabel();
		mainPanel.add(lab);
		lab.setText("<html><b>"+optionName.toString()+"</b> " + option.get("desc") + "</html>");
		lab.setName(optionName.toString());
		JTextField optionField = new JTextField();
		if (option.get("default") != null) 
			optionField.setText(option.get("default").toString());
		else if (optionName.equals("LHOST"))
			optionField.setText(MsfguiApp.getLocalIp());
		optionField.setName("field" + optionName);
		mainPanel.add(optionField);
		elementVector.add(new Component[]{lab,optionField});
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
        descriptionLabel = new javax.swing.JLabel();
        titleLabel = new javax.swing.JLabel();
        encoderLabel = new javax.swing.JLabel();
        generateButton = new javax.swing.JButton();
        versionLabel = new javax.swing.JLabel();
        licenseLabel = new javax.swing.JLabel();
        authorsLabel = new javax.swing.JLabel();
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

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setName("Form"); // NOI18N

        jScrollPane1.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jScrollPane1.setName("jScrollPane1"); // NOI18N

        mainPanel.setName("mainPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(msfgui.MsfguiApp.class).getContext().getResourceMap(PayloadPopup.class);
        timesField.setText(resourceMap.getString("timesField.text")); // NOI18N
        timesField.setName("timesField"); // NOI18N

        encoderCombo.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        encoderCombo.setName("encoderCombo"); // NOI18N

        outputCombo.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "c", "elf", "exe", "java", "js_le", "js_be", "perl", "raw", "ruby", "vba", "vbs", "loop-vbs", "asp", "war", "macho" }));
        outputCombo.setSelectedIndex(2);
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

        descriptionLabel.setText(resourceMap.getString("descriptionLabel.text")); // NOI18N
        descriptionLabel.setName("descriptionLabel"); // NOI18N

        titleLabel.setText(resourceMap.getString("titleLabel.text")); // NOI18N
        titleLabel.setName("titleLabel"); // NOI18N

        encoderLabel.setText(resourceMap.getString("encoderLabel.text")); // NOI18N
        encoderLabel.setName("encoderLabel"); // NOI18N

        generateButton.setText(resourceMap.getString("generateButton.text")); // NOI18N
        generateButton.setName("generateButton"); // NOI18N
        generateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateButtonActionPerformed(evt);
            }
        });

        versionLabel.setText(resourceMap.getString("versionLabel.text")); // NOI18N
        versionLabel.setName("versionLabel"); // NOI18N

        licenseLabel.setText(resourceMap.getString("licenseLabel.text")); // NOI18N
        licenseLabel.setName("licenseLabel"); // NOI18N

        authorsLabel.setText(resourceMap.getString("authorsLabel.text")); // NOI18N
        authorsLabel.setName("authorsLabel"); // NOI18N

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

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(outputScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 1026, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(titleLabel, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(descriptionLabel, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(authorsLabel, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(licenseLabel, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(versionLabel, javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, mainPanelLayout.createSequentialGroup()
                                .addComponent(generateButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(displayButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(saveButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(handleButton))
                            .addGroup(mainPanelLayout.createSequentialGroup()
                                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(encoderLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(outputLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(timesLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(outputPathLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                    .addComponent(templateLabel)
                                    .addComponent(archLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(mainPanelLayout.createSequentialGroup()
                                        .addComponent(templateField, javax.swing.GroupLayout.DEFAULT_SIZE, 218, Short.MAX_VALUE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(templateButton, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(archField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 311, Short.MAX_VALUE)
                                    .addComponent(timesField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 311, Short.MAX_VALUE)
                                    .addComponent(outputCombo, javax.swing.GroupLayout.Alignment.LEADING, 0, 311, Short.MAX_VALUE)
                                    .addComponent(encoderCombo, javax.swing.GroupLayout.Alignment.LEADING, 0, 311, Short.MAX_VALUE)
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, mainPanelLayout.createSequentialGroup()
                                        .addComponent(outputPathField, javax.swing.GroupLayout.PREFERRED_SIZE, 213, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(choosePathButton, javax.swing.GroupLayout.PREFERRED_SIZE, 91, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(templateWorkingCheck)
                                .addGap(154, 154, 154)))
                        .addGap(195, 195, 195))))
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(titleLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(descriptionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(authorsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(licenseLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(versionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(generateButton)
                    .addComponent(displayButton)
                    .addComponent(saveButton)
                    .addComponent(handleButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(outputScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 374, Short.MAX_VALUE)
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
                .addContainerGap())
        );

        jScrollPane1.setViewportView(mainPanel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 922, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 752, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

	private void generateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateButtonActionPerformed
		try {
			Map options = new HashMap();
			for(Object obj : elementVector){
				 String name = ((JLabel)((Component[])obj)[0]).getName();
				 String val = ((JTextField)((Component[])obj)[1]).getText();
				 if(val.length() > 0)
					 options.put(name, val);
			}
			Map data = (Map) rpcConn.execute("module.execute", "payload", fullName,options);
			//Basic info
			if(!data.get("result").equals("success"))
				return;
			String rawHex = data.get("payload").toString();

			if(saveButton.isSelected()){ //Encode and output
				byte[] buffer = new byte[rawHex.length() / 2];
				for (int i = 0; i < rawHex.length(); i += 2) 
					buffer[i/2] = (byte)Integer.parseInt(rawHex.substring(i, i + 2),16);

				options.put("format", outputCombo.getSelectedItem().toString());
				if(timesField.getText().length() > 0)
					options.put("ecount", timesField.getText());
				if(archField.getText().length() > 0)
					options.put("arch", archField.getText());
				if(templateField.getText().length() > 0){
					options.put("altexe", templateField.getText());
					if(templateWorkingCheck.isSelected())
						options.put("inject", true);
				}
				Map encoded = (Map) rpcConn.execute("module.encode", Base64.encode(buffer), 
						encoderCombo.getSelectedItem().toString(),options);
				FileOutputStream fout = new FileOutputStream(outputPathField.getText());
				fout.write(Base64.decode(encoded.get("encoded").toString()));
				fout.close();
				return;
			}

			outputPane.setText("Payload "+fullName+" "+options+" "+(rawHex.length()/2)+" bytes.");
			boolean isPlain = true;
			StringBuilder plain = new StringBuilder("");
			for(int i = 0; i < rawHex.length(); i += 2){
				int chint = Integer.parseInt(rawHex.substring(i,i+2),16);
				if (!Character.isISOControl(chint))// or check isLetterOrDigit isWhitespace or " , . (){}-_+=<>.,?/'"; etc.
					plain.append((char)chint);
				else
					isPlain = false;
			}
			if(isPlain)
				outputPane.append("\n\nplain text\n"+plain);
			StringBuilder rubyHex = new StringBuilder("\"");
			for(int i = 0; i < rawHex.length(); i += 20){
				for(int j = 0; j < 20 && i + j + 2 <= rawHex.length(); j += 2){
					rubyHex.append("\\x");
					rubyHex.append(rawHex.substring(i + j, i + j + 2));
				}
				rubyHex.append("\"");
				if(i + 20 < rawHex.length())
					rubyHex.append("+\n\"");
			}
			outputPane.append("\n\nruby\n"+rubyHex);
		} catch (MsfException ex) {
			JOptionPane.showMessageDialog(this, ex);
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this, ex);
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
		Map hash = new HashMap();
		for(Object obj : elementVector){
			String optName = ((JLabel)((Component[])obj)[0]).getName();
			String optVal = ((JTextField)((Component[])obj)[1]).getText();
			Object defaultVal = ((Map)options.get(optName)).get("default");
			//only need non-default vals
			if(defaultVal == null && optVal.length() > 0 && (!optName.equals("WORKSPACE") || !optVal.equals("default"))
					|| (defaultVal != null && !optVal.equals(defaultVal.toString())))
				hash.put(optName, optVal);
		}
		hash.put("PAYLOAD",fullName);
		hash.put("TARGET","0");
		try{
			rpcConn.execute("module.execute","exploit", "multi/handler", hash);
			MsfguiApp.addRecentModule(java.util.Arrays.asList(new Object[]{"exploit", "multi/handler", hash}), rpcConn, mainFrame);
		}catch (MsfException ex){
			JOptionPane.showMessageDialog(this, ex);
		}
	}//GEN-LAST:event_handleButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField archField;
    private javax.swing.JLabel archLabel;
    private javax.swing.JLabel authorsLabel;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton choosePathButton;
    private javax.swing.JLabel descriptionLabel;
    private javax.swing.JRadioButton displayButton;
    private javax.swing.JComboBox encoderCombo;
    private javax.swing.JLabel encoderLabel;
    private javax.swing.JButton generateButton;
    private javax.swing.JButton handleButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel licenseLabel;
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
    private javax.swing.JLabel titleLabel;
    private javax.swing.JLabel versionLabel;
    // End of variables declaration//GEN-END:variables

}
