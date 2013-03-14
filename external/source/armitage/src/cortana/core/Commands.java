package cortana.core;

import java.util.*;

import sleep.runtime.*;
import sleep.interfaces.*;
import sleep.engine.*;
import sleep.bridges.*;

public class Commands implements Function, Environment, Loadable {
	protected CommandManager manager;

	public void scriptLoaded(ScriptInstance si) {
		Hashtable environment = si.getScriptEnvironment().getEnvironment();

		environment.put("&command", this);
		environment.put("command", this);

		environment.put("&fire_command", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}

	public void bindFunction(ScriptInstance si, String type, String command, Block body) {
		SleepClosure f = new SleepClosure(si, body);
		manager.registerCommand(command, f);
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		String command = BridgeUtilities.getString(args, "");
		if (name.equals("&fire_command")) {
			StringBuffer arstring = new StringBuffer();
			LinkedList l = new LinkedList(args);
			l.add(command);
			Collections.reverse(l);
			Iterator i = l.iterator();
			while (i.hasNext()) {
				arstring.append(i.next() + "");
				if (i.hasNext())
					arstring.append(" ");
			}

			manager.fireCommand(command, arstring + "", args);
			return SleepUtils.getEmptyScalar();
		}
		else {
			SleepClosure f = BridgeUtilities.getFunction(args, script);
			manager.registerCommand(command, f);
			return SleepUtils.getEmptyScalar();
		}
	}

	public Commands(CommandManager m) {
		this.manager = m;
	}
}
