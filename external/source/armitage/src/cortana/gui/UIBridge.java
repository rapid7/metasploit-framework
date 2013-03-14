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

/* some methods to help out with user interface stuff */
public class UIBridge implements Loadable, Function {
	protected ArmitageApplication armitage;

	public UIBridge(ArmitageApplication a) {
		armitage = a;
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&later")) {
			final SleepClosure f = BridgeUtilities.getFunction(args, script);
			final Stack argz = EventManager.shallowCopy(args);
			if (SwingUtilities.isEventDispatchThread()) {
				SleepUtils.runCode(f, "laterz", null, argz);
			}
			else {
				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						SleepUtils.runCode(f, "laterz", null, argz);
					}
				});
			}
		}

		return SleepUtils.getEmptyScalar();
	}

	public void scriptLoaded(ScriptInstance si) {
		si.getScriptEnvironment().getEnvironment().put("&later",  this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}
}
