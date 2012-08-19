package cortana.gui;

import cortana.core.*;
import msf.*;
import armitage.*;
import ui.*;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import java.util.*;

import java.io.IOException;

/* an API to bind new menus in Armitage */
public class MenuBridge implements Loadable, Function, Environment {
	protected ArmitageApplication armitage;
	protected Stack               parents = new Stack();
	protected Map                 menus   = new HashMap();
	protected Stack               data    = new Stack();

	public Stack getArguments() {
		return (Stack)data.peek();
	}

	public MenuBridge(ArmitageApplication a) {
		armitage = a;
	}

	public void push(JComponent menu, Stack arguments) {
		parents.push(menu);
		data.push(arguments);
	}

	public void pop() {
		parents.pop();
		data.pop();
	}

	public JComponent getTopLevel() {
		if (parents.isEmpty()) {
			throw new RuntimeException("menu has no parent");
		}
		else {
			return (JComponent)parents.peek();
		}
	}

	public void bindFunction(ScriptInstance si, String name, String desc, Block body) {
		SleepClosure f = new SleepClosure(si, body);
		if (name.equals("menu")) {
			createMenu(desc, f);
		}
		else if (name.equals("item")) {
			createItem(desc, f);
		}
		else if (name.equals("popup")) {
			registerTopLevel(desc, f);
		}
	}

	public void registerTopLevel(String name, SleepClosure f) {
		if (!menus.containsKey(name))
			menus.put(name, new LinkedList());

		LinkedList m = (LinkedList)menus.get(name);
		m.add(f);
	}

	public boolean isPopulated(String name) {
		return menus.containsKey(name) && ((LinkedList)menus.get(name)).size() > 0;
	}

	public LinkedList getMenus(String name) {
		if (menus.containsKey(name))
			return (LinkedList)menus.get(name);
		else
			return new LinkedList();
	}

	public void createMenu(String name, SleepClosure f) {
		JComponent top = getTopLevel();
		JMenu next = new ScriptedMenu(name, f, this);
		top.add(next);
	}

	public void createItem(String name, SleepClosure f) {
		JComponent top = getTopLevel();
		JMenuItem next = new ScriptedMenuItem(name, f, this);
		top.add(next);
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&separator")) {
			if (getTopLevel() instanceof JMenu) {
				((JMenu)getTopLevel()).addSeparator();
			}
			else if (getTopLevel() instanceof JPopupMenu) {
				((JPopupMenu)getTopLevel()).addSeparator();
			}
		}
		else if (name.equals("&show_menu")) {
			String hook  = BridgeUtilities.getString(args, "");

			if (args.size() > 0) {
				armitage.setupMenu(getTopLevel(), hook, cortana.core.EventManager.shallowCopy(args));
			}
			else {
				armitage.setupMenu(getTopLevel(), hook, getArguments());
			}
		}
		else if (name.equals("&show_popup")) {
			MouseEvent ev = (MouseEvent)BridgeUtilities.getObject(args);
			String hook  = BridgeUtilities.getString(args, "");

			JPopupMenu popup = new JPopupMenu();
			push(popup, cortana.core.EventManager.shallowCopy(args));
			armitage.setupMenu(getTopLevel(), hook, getArguments());
			pop();
			popup.show((JComponent)ev.getSource(), ev.getX(), ev.getY());
		}
		else if (name.equals("&insert_menu")) {
			JMenu parent = (JMenu)BridgeUtilities.getObject(args);
			String hook  = BridgeUtilities.getString(args, "");

			push(parent, cortana.core.EventManager.shallowCopy(args));
			armitage.setupMenu(getTopLevel(), hook, getArguments());
			pop();
		}
		else if (name.equals("&menubar")) {
			final String _label = BridgeUtilities.getString(args, "");
			final String hook   = BridgeUtilities.getString(args, "");
			int    offset = BridgeUtilities.getInt(args, 2);
			DynamicMenu menu = new DynamicMenu("");

			/* setup the menu's title */
			if (_label.indexOf('&') > -1) {
				menu.setText( _label.substring(0, _label.indexOf('&')) + _label.substring(_label.indexOf('&') + 1, _label.length()) );
				menu.setMnemonic(_label.charAt(_label.indexOf('&') + 1));
			}
			else {
				menu.setText(_label);
			}

			/* setup the hook for the menu... */
			menu.setHandler(new DynamicMenu.DynamicMenuHandler() {
				public void setupMenu(JMenu parent) {
					armitage.setupMenu(parent, hook, new Stack());

					if (!isPopulated(hook)) {
						armitage.getJMenuBar().remove(parent);
						armitage.getJMenuBar().validate();
					}
				}
			});

			/* make sure no other menu exists with the same name */
			MenuElement[] menus = armitage.getJMenuBar().getSubElements();
			for (int x = 0; x < menus.length; x++) {
				JMenu temp = (JMenu)menus[x].getComponent();
				if (temp.getText().equals(menu.getText()))
					armitage.getJMenuBar().remove(temp);
			}

			/* add the menu to our menubar (to the left of the help menu) */
			int index = armitage.getJMenuBar().getComponentCount() - offset;
			armitage.getJMenuBar().add(menu, index >= 0 ? index : 0);

			/* force the component to update itself */
			armitage.getJMenuBar().validate();
		}
		else {
			String desc = BridgeUtilities.getString(args, "");
			SleepClosure f = BridgeUtilities.getFunction(args, script);

			if (name.equals("&menu")) {
				createMenu(desc, f);
			}
			else if (name.equals("&item")) {
				createItem(desc, f);
			}
			else if (name.equals("&popup")) {
				registerTopLevel(desc, f);
			}
		}
		return SleepUtils.getEmptyScalar();
	}

	public void scriptLoaded(ScriptInstance si) {
		si.getScriptEnvironment().getEnvironment().put("popup", this);
		si.getScriptEnvironment().getEnvironment().put("&popup",  this);

		si.getScriptEnvironment().getEnvironment().put("menu", this);
		si.getScriptEnvironment().getEnvironment().put("&menu",  this);

		si.getScriptEnvironment().getEnvironment().put("item", this);
		si.getScriptEnvironment().getEnvironment().put("&item",  this);

		si.getScriptEnvironment().getEnvironment().put("&separator", this);
		si.getScriptEnvironment().getEnvironment().put("&menubar",   this);
		si.getScriptEnvironment().getEnvironment().put("&show_menu", this);
		si.getScriptEnvironment().getEnvironment().put("&insert_menu", this);
		si.getScriptEnvironment().getEnvironment().put("&show_popup", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}
}
