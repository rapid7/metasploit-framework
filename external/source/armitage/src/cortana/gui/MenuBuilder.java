package cortana.gui;

import cortana.core.*;
import msf.*;
import armitage.*;
import ui.*;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;

import java.io.IOException;

/* an API to bind new menus in Armitage */
public class MenuBuilder {
	protected ArmitageApplication armitage;
	protected MenuBridge bridge;

	public MenuBuilder(ArmitageApplication a) {
		armitage = a;
		bridge   = new MenuBridge(a);
	}

	public Loadable getBridge() {
		return bridge;
	}

	public void installMenu(MouseEvent ev, String key, Stack argz) {
		if (ev.isPopupTrigger() && bridge.isPopulated(key)) {
			JPopupMenu menu = new JPopupMenu();
			setupMenu(menu, key, argz);

			/* we check, because it may have changed its mind after setupMenu failed */
			if (bridge.isPopulated(key)) {
				menu.show((JComponent)ev.getSource(), ev.getX(), ev.getY());
				ev.consume();
			}
		}
	}

	public void setupMenu(JComponent parent, String key, Stack argz) {
		if (!bridge.isPopulated(key))
			return;

		/* setup the menu */
		bridge.push(parent, argz);

		Iterator i = bridge.getMenus(key).iterator();
		while (i.hasNext()) {
			SleepClosure f = (SleepClosure)i.next();
			if (f.getOwner().isLoaded()) {
				SleepUtils.runCode(f, key, null, cortana.core.EventManager.shallowCopy(argz));
			}
			else {
				i.remove();
			}
		}

		bridge.pop();
	}
}
