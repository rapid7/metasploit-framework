package msfgui;

import java.awt.Color;
import java.awt.Component;
import java.awt.HeadlessException;
import java.util.Map;
import javax.swing.JComponent;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.metal.DefaultMetalTheme;
import javax.swing.plaf.metal.MetalLookAndFeel;

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
		props = MsfguiApp.getPropertiesNode();
		if(Boolean.TRUE.equals(props.get("overrideColors")) && props.containsKey("backgroundColor")){
			final Color bgcol = new Color((Integer)props.get("backgroundColor"));
			final Color fgcol = new Color((Integer)props.get("foregroundColor"));
			UIManager.put("nimbusBase", bgcol);
			UIManager.put("nimbusBlueGrey", bgcol);
			UIManager.put("control", bgcol);
			UIManager.put("nimbusLightBackground", bgcol);
			UIManager.put("nimbusSelectedText", bgcol);
			UIManager.put("textHighlightText", bgcol);
			UIManager.put("textForeground", fgcol);
			UIManager.put("menuText", fgcol);
			UIManager.put("infoText", fgcol);
			UIManager.put("controlText", fgcol);
			UIManager.put("text", fgcol);
			MetalLookAndFeel.setCurrentTheme(new DefaultMetalTheme() {
				public String getName() {return "msfgui custom";}
				private final ColorUIResource foreground = new ColorUIResource(fgcol);
				private final ColorUIResource background = new ColorUIResource(bgcol);
				protected ColorUIResource getPrimary1() {return foreground;}
				protected ColorUIResource getPrimary2() {return foreground;}
				protected ColorUIResource getPrimary3() {return foreground;}
				protected ColorUIResource getSecondary1() {return foreground;}
				protected ColorUIResource getSecondary2() {return background;}
				protected ColorUIResource getSecondary3() {return background;}
				public ColorUIResource getMenuSelectedForeground() {return background;}
				public ColorUIResource getMenuSelectedBackground() {return foreground;}
				protected ColorUIResource getBlack() {return foreground;}
				protected ColorUIResource getWhite() {return background;}
			});
		}

		String classname=""+MsfguiApp.getPropertiesNode().get("LnF");
		try {
			boolean system = !"Metal".equals(props.get("LnF"));
			try{
				UIManager.setLookAndFeel(classname);
				props.put("LnF", classname);
			}catch(Exception ulafex){
				String newLnF = UIManager.getSystemLookAndFeelClassName();
				//Prefer nimbus
				for(LookAndFeelInfo lookAndFeel : UIManager.getInstalledLookAndFeels())
					if(lookAndFeel.getClassName().equals("com.sun.java.swing.plaf.nimbus.NimbusLookAndFeel"))
						newLnF = "com.sun.java.swing.plaf.nimbus.NimbusLookAndFeel";
				UIManager.setLookAndFeel(newLnF);
				props.put("LnF", newLnF);
			}
		} catch (Exception e) {
			MsfguiApp.showMessage(null, e);
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
		if(Boolean.TRUE.equals(props.get("overrideColors"))){
			if(props.containsKey("backgroundColor"))
				com.setBackground(new Color((Integer)props.get("backgroundColor")));
			if(props.containsKey("foregroundColor"))
				com.setForeground(new Color((Integer)props.get("foregroundColor")));
		}

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
