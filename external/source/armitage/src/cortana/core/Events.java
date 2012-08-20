package cortana.core;

import java.util.*;

import sleep.runtime.*;
import sleep.interfaces.*;
import sleep.engine.*;
import sleep.bridges.*;

public class Events implements Function, Environment, Loadable {
	protected EventManager manager;

	public void scriptLoaded(ScriptInstance si) {
		Hashtable environment = si.getScriptEnvironment().getEnvironment();

		environment.put("&on", this);
		environment.put("on", this);

		environment.put("&when", this);
		environment.put("when", this);

		environment.put("&fire_event", this);
		environment.put("&fire_event_async", this);
		environment.put("&fire_event_local", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}

	protected void addListener(String name, SleepClosure c, boolean temp) {
		manager.addListener(name, c, temp);
	}

	public void bindFunction(ScriptInstance si, String type, String event, Block body) {
		boolean temporary = type.equals("when") ? true : false;
		SleepClosure f = new SleepClosure(si, body);
		addListener(event, f, temporary);
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&fire_event_async") || name.equals("&fire_event")) {
			String event = BridgeUtilities.getString(args, "");
			manager.fireEventAsync(event, EventManager.shallowCopy(args));
			return SleepUtils.getEmptyScalar();
		}
		else if (name.equals("&fire_event_local")) {
			String event = BridgeUtilities.getString(args, "");
			manager.fireEvent(event, args, script);
			return SleepUtils.getEmptyScalar();
		}
		else {
			boolean temporary = name.equals("&when") ? true : false;
			String event = BridgeUtilities.getString(args, "");
			SleepClosure f = BridgeUtilities.getFunction(args, script);
			addListener(event, f, temporary);
			return SleepUtils.getEmptyScalar();
		}
	}

	public Events(EventManager m) {
		this.manager = m;
	}
}
