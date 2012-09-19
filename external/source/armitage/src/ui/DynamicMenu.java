package ui;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;

public class DynamicMenu extends JMenu implements MenuListener {
	public DynamicMenu(String s) {
		super(s);
		addMenuListener(this);
	}

	public void setHandler(DynamicMenuHandler h) {
		handler = h;
	}

	protected DynamicMenuHandler handler = null;

	public interface DynamicMenuHandler {
		public void setupMenu(JMenu parent);
	}

	public void menuSelected(MenuEvent ev) {
		if (handler != null) {
			handler.setupMenu(this);
		}
	}

	public void menuCanceled(MenuEvent ev) {
		removeAll();
	}

	public void menuDeselected(MenuEvent ev) {
		removeAll();
	}
}

