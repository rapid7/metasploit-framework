package msfgui;

import java.awt.HeadlessException;

/**
 * Basic frame; shows default icon
 * @author scriptjunkie
 */
public class MsfFrame extends javax.swing.JFrame{

	public MsfFrame(String title) throws HeadlessException {
		super(title);
		org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(
				msfgui.MsfguiApp.class).getContext().getResourceMap(ModulePopup.class);
		this.setIconImage(resourceMap.getImageIcon("main.icon").getImage());
	}

	public MsfFrame() throws HeadlessException {
		this("");
	}

}
