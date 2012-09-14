package cortana.gui;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;

import sleep.runtime.*;
import sleep.engine.*;
import sleep.bridges.*;

import java.util.*;

/* implements a scripted menu */
public class ScriptedMenu extends JMenu implements MenuListener {
	protected MenuBridge   bridge;
	protected SleepClosure f;
	protected String       label;
	protected Stack        args;

	public ScriptedMenu(String _label, SleepClosure f, MenuBridge bridge) {
		if (_label.indexOf('&') > -1) {
			setText( _label.substring(0, _label.indexOf('&')) + _label.substring(_label.indexOf('&') + 1, _label.length()) );
			setMnemonic(_label.charAt(_label.indexOf('&') + 1));
		}
		else {
			setText(_label);
		}

		this.label  = _label;
		this.bridge = bridge;
		this.f      = f;
		this.args   = bridge.getArguments();
		addMenuListener(this);
	}

	public void menuSelected(MenuEvent e) {
		bridge.push(this, args);
		SleepUtils.runCode(f, label, null, cortana.core.EventManager.shallowCopy(args));
		bridge.pop();
	}

	public void menuDeselected(MenuEvent e) {
		removeAll();
	}

	public void menuCanceled(MenuEvent e) {
		removeAll();
	}
}
