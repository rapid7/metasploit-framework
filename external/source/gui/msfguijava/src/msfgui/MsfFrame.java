package msfgui;

import java.awt.Component;
import java.awt.HeadlessException;
import java.util.Map;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

/**
 * Basic frame; shows default icon and saves dimensions on resize.
 * Also handles UI functions across windows
 * 
 * @author scriptjunkie
 */
public class MsfFrame extends javax.swing.JFrame{
	private static Map props = null;
	private String frameClass = null;

	/** Sets look and feel to preset or default */
	public static void setLnF(){
		String classname=""+MsfguiApp.getPropertiesNode().get("LnF");
		Map info = MsfguiApp.getPropertiesNode();
		try {
			boolean system = !"Metal".equals(info.get("LnF"));
			try{
				UIManager.setLookAndFeel(classname);
				info.put("LnF", classname);
			}catch(Exception ulafex){
				String newLnF = UIManager.getSystemLookAndFeelClassName();
				//Prefer nimbus
				for(LookAndFeelInfo lookAndFeel : UIManager.getInstalledLookAndFeels())
					if(lookAndFeel.getClassName().equals("com.sun.java.swing.plaf.nimbus.NimbusLookAndFeel"))
						newLnF = "com.sun.java.swing.plaf.nimbus.NimbusLookAndFeel";
				UIManager.setLookAndFeel(newLnF);
				info.put("LnF", newLnF);
			}
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e);
			e.printStackTrace();
		}
	}

	/**
	 * Applies any UI changes to all frames.
	 */
	public static void updateUIs(){
		setLnF();
		for(java.awt.Frame fram : java.awt.Frame.getFrames()){
			updateSizes(fram);
			javax.swing.SwingUtilities.updateComponentTreeUI(fram);
			fram.pack();
		}
	}

	/**
	 * Recursively iterates through a container, updating the size
	 *
	 * @param c Container or component to be resized
	 */
	public static void updateSizes(java.awt.Component com) {
		//Make sure props is initialized
		if(props == null)
			props = MsfguiApp.getPropertiesNode();

		//Reset size
		if(com instanceof JComponent && props.containsKey("jComponentSizeVariant"))
			((JComponent)com).putClientProperty("JComponent.sizeVariant", props.get("jComponentSizeVariant"));
		java.awt.Font fnt = com.getFont();
		if(fnt != null && props.containsKey("defaultTextSize"))
			com.setFont(fnt.deriveFont(new Float(props.get("defaultTextSize").toString()).floatValue()));

		//Loop through containers
		if(com instanceof javax.swing.JMenu)
			for(Component cc : ((javax.swing.JMenu)com).getMenuComponents())
				updateSizes(cc);
		else if(com instanceof java.awt.Container)
			for(Component cc : ((java.awt.Container)com).getComponents())
				updateSizes(cc);
	}

	public MsfFrame(String title) throws HeadlessException {
		super(title);
		org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(
				msfgui.MsfguiApp.class).getContext().getResourceMap(ModulePopup.class);
		this.setIconImage(resourceMap.getImageIcon("main.icon").getImage());
	}

	/**
	 * Checks to see if this frame has saved height and width, and reloads it.
	 */
	public void loadSavedSize(){
		props = MsfguiApp.getPropertiesNode();
		updateSizes(this);
		//Do inital setup if needed
		if(frameClass == null){
			frameClass = getClass().getName();

			//And update saved height/width data on resize
			addComponentListener(new java.awt.event.ComponentAdapter() {
				public void componentResized(java.awt.event.ComponentEvent e) {
					props.put(frameClass +"Width", getWidth());
					props.put(frameClass +"Height", getHeight());
				}
			});
		}
		//Reset the size
		if(props.containsKey(frameClass+"Width") && props.containsKey(frameClass+"Height"))
			setSize((Integer)props.get(frameClass+"Width"),
					(Integer)props.get(frameClass+"Height"));
	}

	public MsfFrame() throws HeadlessException {
		this("");
	}
}
