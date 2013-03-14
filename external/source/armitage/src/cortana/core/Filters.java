package cortana.core;

import java.util.*;

import sleep.runtime.*;
import sleep.interfaces.*;
import sleep.engine.*;
import sleep.bridges.*;

public class Filters implements Function, Environment, Loadable {
	protected FilterManager manager;

	public void scriptLoaded(ScriptInstance si) {
		Hashtable environment = si.getScriptEnvironment().getEnvironment();

		environment.put("filter", this);
		environment.put("&filter_data", this);
		environment.put("&filter_data_array", this);
		environment.put("&filterd", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}

	protected void addFilter(String name, SleepClosure c) {
		manager.addFilter(name, c);
	}

	public void bindFunction(ScriptInstance si, String type, String event, Block body) {
		SleepClosure f = new SleepClosure(si, body);
		addFilter(event, f);
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&filter_data")) {
			String event = BridgeUtilities.getString(args, "");
			Stack results =  manager.filterScalarData(event, args);
			Scalar r = SleepUtils.getArrayScalar();

			while (!results.isEmpty()) {
				r.getArray().push((Scalar)results.pop());
			}

			return r;
		}
		else if (name.equals("&filter_data_array")) {
			Stack argz = new Stack();
			Scalar event = BridgeUtilities.getScalar(args);

			ScalarArray temp = BridgeUtilities.getArray(args);
			while (temp.size() > 0) {
				argz.push(temp.pop());
			}

			argz.push(event);
			return evaluate("&filter_data", script, argz);
		}
		else {
			String event = BridgeUtilities.getString(args, "");
			SleepClosure f = BridgeUtilities.getFunction(args, script);
			addFilter(event, f);
			return SleepUtils.getEmptyScalar();
		}
	}

	public Filters(FilterManager m) {
		this.manager = m;
	}
}
