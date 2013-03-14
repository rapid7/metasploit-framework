package cortana.gui;

import sleep.runtime.*;
import sleep.bridges.*;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import java.util.*;

public class ScriptedMenuItem extends JMenuItem implements ActionListener {
	protected String       label;
	protected SleepClosure code;
	protected MenuBridge   bridge;
	protected Stack        args;

	public ScriptedMenuItem(String label, SleepClosure code, MenuBridge bridge) {
		if (label.indexOf('&') > -1) {
			setText( label.substring(0, label.indexOf('&')) +
					label.substring(label.indexOf('&') + 1, label.length())
				);
			setMnemonic(label.charAt(label.indexOf('&') + 1));
		}
		else {
			setText(label);
		}

		this.code   = code;
		this.bridge = bridge;
		this.label  = label;
		args = bridge.getArguments();
		addActionListener(this);
	}

	public void actionPerformed(ActionEvent ev) {
		SleepUtils.runCode(code, label, null, cortana.core.EventManager.shallowCopy(args));
	}
}
