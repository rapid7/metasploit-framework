package msfgui;

import java.awt.HeadlessException;
import java.util.Map;

/**
 * Basic frame; shows default icon and saves dimensions on resize
 * 
 * @author scriptjunkie
 */
public class MsfFrame extends javax.swing.JFrame{
	private Map props;
	private String frameClass = null;

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
