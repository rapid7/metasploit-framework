package msfgui;

import java.awt.Component;
import java.awt.HeadlessException;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * Provides methods of extracting information about a module and displaying it,
 * especially options
 *
 * @author scriptjunkie
 */
public abstract class ModuleInfoWindow extends MsfFrame {
	protected String moduleType;
	protected String fullName;
	protected RpcConnection rpcConn;
	protected JLabel authorsLabel;
	protected JLabel titleLabel;
	protected JLabel licenseLabel;
	protected JLabel versionLabel;
	protected MainFrame parentFrame;
	protected ArrayList requiredOpts; // I love how these options aren't optional
	protected ArrayList optionalOpts;
	protected ArrayList advancedOpts;
	protected Map options; //this holds the complete options returned from RPC
	private JComponent descriptionBox = null;

	public ModuleInfoWindow(){
		authorsLabel = new javax.swing.JLabel();
		licenseLabel = new javax.swing.JLabel();
		versionLabel = new javax.swing.JLabel();
		titleLabel = new javax.swing.JLabel();
	}
	/**
	 * Queries metasploit for information about this module, displaying it in the
	 * basic labels that it knows about.
	 * @param rpcConn
	 * @param fullName
	 * @return
	 */
	protected Map showBasicInfo(final RpcConnection rpcConn, final String fullName){
		Map info = (Map) rpcConn.execute("module.info", moduleType, fullName);
		//Basic info
		setTitle(info.get("name") + " " + fullName);
		try{
		titleLabel.setText("<html><h2>"+info.get("name")+ "</h2> <b>Rank:</b> "+Rank.toString(info.get("rank"))+"</html>");
		}
		catch(Exception ex){
			System.out.println(info);
		}
		Object references = info.get("references");
		StringBuilder referenceString = new StringBuilder();
		if(references != null){
			List refList = (List)references;
			if(refList.size() > 0)
				referenceString.append("<br>References:<br>");
			for(Object refo : refList){
				List ref = (List)refo;
				referenceString.append(ref.get(0)).append(": ").append(ref.get(1)).append("<br> ");
			}
			referenceString.append("<br>");
		}
		//Attempt to call setText on descriptionBox. This convolutedness is necessary since JLabels and 
		//JEditorPanes do not have a common ancestor that we can call setText on.
		try{
			descriptionBox = (JComponent)getClass().getField("descriptionBox").get(this);
			descriptionBox.getClass().getMethod("setText", String.class).invoke(descriptionBox, 
				"<html><b>Description</b> "+info.get("description").toString().replaceAll("\\s+", " ")+referenceString+"</html>");
		}catch(Exception ex){
			javax.swing.JOptionPane.showMessageDialog(this, ex);
		}
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
		updateSizes(this);
		return info;
	}

   /** Displays exploit and payload options. */
	protected void showOptions(JPanel mainPanel, String payload) {
		for(Object o : requiredOpts)
			mainPanel.remove((Component)o);
		requiredOpts.clear();
		for(Object o : optionalOpts)
			mainPanel.remove((Component)o);
		optionalOpts.clear();
		for(Object o : advancedOpts)
			mainPanel.remove((Component)o);
		advancedOpts.clear();
		try{
			//get options
			options = (Map) rpcConn.execute("module.options", moduleType, fullName);
			// payload options
			if(moduleType.equals("exploit")){
				options.putAll((Map) rpcConn.execute("module.options", "payload", payload));
				Map encodingOpt = new HashMap();
				encodingOpt.put("desc", "Preferred encoding or encodings for the payload.");
				encodingOpt.put("required", Boolean.FALSE);
				encodingOpt.put("advanced", Boolean.TRUE);
				encodingOpt.put("evasion", Boolean.TRUE);
				options.put("Encoder", encodingOpt);
			}
			//Display each option
			for (Object optionName : options.keySet()) {
				Map option = (Map)options.get(optionName); //{desc=blah, evasion=fals, advanced=false, required=true, type=port, default=blah}
				javax.swing.JLabel tempText = new javax.swing.JLabel();
				tempText.setText("<html><b>"+optionName.toString()+"</b> " + option.get("desc") + "</html>");
				tempText.setBorder(null);
				//Width calculation; some of these descriptions are pretty long
				//so we need to limit to the size of elements already on the page
				//like licenseLabel unless it doesn't exist, then guess based on parent
				int mywidth = licenseLabel.getWidth();
				java.awt.Dimension tempsize = tempText.getPreferredSize();
				if(mywidth == 0)
					mywidth = mainPanel.getParent().getWidth() * 2 / 3;
				//if we are going to squish it, give it room to wrap vertically
				if(mywidth < tempsize.width)
					tempText.setPreferredSize(new java.awt.Dimension(mywidth,tempsize.height
							*(1+tempsize.width/mywidth)));
				tempText.setVerticalAlignment(javax.swing.JLabel.BOTTOM);
				mainPanel.add(tempText);//mainPanel.add(containerPane);
				tempText.setFont(authorsLabel.getFont());
				JComponent optionField;
				Object type = option.get("type");

				//Add different types of input elements for the different types of options
				if ("bool".equals(type)){ //bool options get checkboxes
					optionField = new JCheckBox("",Boolean.TRUE.equals(option.get("default")));
				} else if ("enum".equals(type)){ //enum options get combo boxes
					JComboBox optionCombo = new JComboBox();
					List enums = (List)option.get("enums");
					for(Object opt : enums)
						optionCombo.addItem(opt);
					optionCombo.setSelectedItem(option.get("default"));
					optionField = optionCombo;
				} else {
					JTextField optionTextField;
					if("port".equals(type) || "integer".equals(type)){
						NumberFormat nf = NumberFormat.getIntegerInstance();
						nf.setGroupingUsed(false);
						optionTextField = new JFormattedTextField(nf);
					} else {// "address"  "string"
						optionTextField = new JTextField();
					}
					if (option.get("default") != null) {
						optionTextField.setText(option.get("default").toString());
					} else if (optionName.equals("LHOST")){ //try to find local ip
						optionTextField.setText(MsfguiApp.getLocalIp());
					} else if (optionName.equals("WORKSPACE")){
						optionTextField.setText(MsfguiApp.workspace);
					} else if (optionName.equals("SESSION") && moduleType.equals("post")
							&& parentFrame.selectedSessions != null
							&& parentFrame.selectedSessions.length > 0){
						optionTextField.setText(parentFrame.selectedSessions[0].get("id").toString());
					}
					optionField = optionTextField;
				}
				optionField.setName("field" + optionName);
				mainPanel.add(optionField);
				if (option.get("advanced").equals(Boolean.FALSE) && option.get("evasion").equals(Boolean.FALSE)){
					if(option.get("required").equals(Boolean.TRUE)){
						requiredOpts.add(tempText);
						requiredOpts.add(optionField);
					}else {
						optionalOpts.add(tempText);
						optionalOpts.add(optionField);
					}
				}else{
					advancedOpts.add(tempText);
					advancedOpts.add(optionField);
				}
			}
		} catch (MsfException ex) {
			MsfguiApp.showMessage(rootPane, ex);
		}
		updateSizes(this);
	}

	/** 
	 * Iterates through the main panel, finding and extracting options.
	 * 
	 * @param mainPanel
	 * @return a map of options the user has selected
	 */
	protected HashMap getOptions(JPanel mainPanel) {
		//Put options into request
		HashMap hash = new HashMap();
		//Get all options by looping over all components, and checking name
		for (Component comp : mainPanel.getComponents()) {
			if (!(comp instanceof JTextField) && !(comp instanceof JCheckBox))
				continue;
			JComponent optionField = (JComponent) comp;
			String optName = optionField.getName().substring("field".length());
			if(!options.containsKey(optName))
				continue;
			Object optVal;
			if (comp instanceof JCheckBox)
				optVal = ((JCheckBox) comp).isSelected();
			else if (comp instanceof JComboBox)
				optVal = ((JComboBox) comp).getSelectedItem();
			else
				optVal = ((JTextField) comp).getText();
			Object defaultVal = ((Map) options.get(optName)).get("default");
			//only need non-default vals
			if (defaultVal == null && optVal.toString().length() > 0 
					&& (!optName.equals("WORKSPACE") || !optVal.equals("default"))
					&& (!optVal.equals(Boolean.FALSE))
					|| (defaultVal != null && !optVal.toString().equals(defaultVal.toString()))) {
				hash.put(optName, optVal.toString()); //msfrpcd likes strings. Give them strings.
			}
		}
		return hash;
	}

	/**
	 * Takes options the user has provided and runs the module
	 * @param console
	 * @param hash
	 * @throws MsfException
	 * @throws HeadlessException
	 */
	protected void run(Map hash, boolean console) throws MsfException, HeadlessException {
		run(moduleType, fullName, hash, console);
	}
	/**
	 * Takes options the user has provided and runs the specified module
	 * @param console
	 * @param hash
	 * @throws MsfException
	 * @throws HeadlessException
	 */
	protected void run(String moduleType, String fullName, Map hash, boolean console) throws MsfException, HeadlessException {
		MsfguiApp.runModule(moduleType,fullName,hash,rpcConn,parentFrame,console);
	}
}
