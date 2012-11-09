package cortana.support;

import java.io.*;
import java.util.*;

import cortana.core.*;
import cortana.metasploit.*;

import sleep.runtime.*;
import sleep.interfaces.*;
import sleep.bridges.*;
import sleep.bridges.io.*;

/** Utilities that don't fit anywhere else... still useful stuff I assume */
public class CortanaUtilities implements Function, Loadable {
	/* we need this to increment loadedScripts by 1 */
	protected MetasploitBridge metasploit;

	public CortanaUtilities(MetasploitBridge metasploit) {
		this.metasploit = metasploit;
	}

	public void scriptLoaded(ScriptInstance script) {
		script.getScriptEnvironment().getEnvironment().put("&spawn", this);
		script.getScriptEnvironment().getEnvironment().put("&fork", this);
		script.getScriptEnvironment().getEnvironment().put("&dispatch_event", this);
		script.getScriptEnvironment().getEnvironment().put("&apply", this);
	}

	public void scriptUnloaded(ScriptInstance script) {
	}

	public void installVars(ScriptVariables vars, ScriptInstance script) {
		ScriptVariables original = script.getScriptVariables();
		if (original.getScalar("$armitage") != null)
			vars.putScalar("$armitage", original.getScalar("$armitage"));

		if (original.getScalar("$preferences") != null)
			vars.putScalar("$preferences", original.getScalar("$preferences"));

		if (original.getScalar("$__script__") != null)
			vars.putScalar("$__script__", original.getScalar("$__script__"));

		if (original.getScalar("$shared") != null)
			vars.putScalar("$shared", original.getScalar("$shared"));
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&fork")) {
			/* this function taken from sleep.bridges.BasicIO. I'm reimplementing it to automatically
			   pass through a few global variables that Cortana relies on */

			SleepClosure   param = BridgeUtilities.getFunction(args, script);

			// create our fork...
			ScriptInstance child = script.fork();
			child.installBlock(param.getRunnableCode());

			ScriptVariables vars = child.getScriptVariables();

			while (!args.isEmpty()) {
				KeyValuePair kvp = BridgeUtilities.getKeyValuePair(args);
				vars.putScalar(kvp.getKey().toString(), SleepUtils.getScalar(kvp.getValue()));
			}

			// install our necessary global variables
			installVars(vars, script);

			// create a pipe between these two items...
			IOObject parent_io = new IOObject();
			IOObject child_io  = new IOObject();

			try {
				PipedInputStream  parent_in  = new PipedInputStream();
				PipedOutputStream parent_out = new PipedOutputStream();
				parent_in.connect(parent_out);

				PipedInputStream  child_in   = new PipedInputStream();
				PipedOutputStream child_out  = new PipedOutputStream();
				child_in.connect(child_out);

				parent_io.openRead(child_in);
				parent_io.openWrite(parent_out);

				child_io.openRead(parent_in);
				child_io.openWrite(child_out);

				child.getScriptVariables().putScalar("$source", SleepUtils.getScalar(child_io));

				Thread temp = new Thread(child, "fork of " + child.getRunnableBlock().getSourceLocation());

				parent_io.setThread(temp);
				child_io.setThread(temp);

				child.setParent(parent_io);

				temp.start();
			}
			catch (Exception ex) {
				script.getScriptEnvironment().flagError(ex);
			}

			return SleepUtils.getScalar(parent_io);
		}
		else if (name.equals("&spawn")) {
			SleepClosure param = BridgeUtilities.getFunction(args, script);

			/* fortunately, Sleep has some nice stuff to make forking convienent */
			ScriptInstance child = script.fork();
			child.installBlock(param.getRunnableCode());

			/* prevent a bad day, reinit metadata in new script as a copy of metadata in old */
			Map meta = Collections.synchronizedMap(new HashMap(script.getMetadata()));
			child.getScriptVariables().getGlobalVariables().putScalar("__meta__", SleepUtils.getScalar((Object)meta));

			/* give our new script instance its own id, so local events trigger here only */
			child.getMetadata().put("%scriptid%", child.hashCode() ^ (System.currentTimeMillis() * 13));

			/* install any variables the user specified */
			ScriptVariables vars = child.getScriptVariables();

			while (!args.isEmpty()) {
				KeyValuePair kvp = BridgeUtilities.getKeyValuePair(args);
				vars.putScalar(kvp.getKey().toString(), SleepUtils.getScalar(kvp.getValue()));
			}

			/* install some key values... */
			installVars(vars, script);

			/* increment the number of installed scripts by 1 */
			synchronized (metasploit) {
				metasploit.loadedScripts += 1;
			}

			/* run the script... this will block as &isolate is not a &fork */
			return child.runScript();
		}
		else if (name.equals("&dispatch_event")) {
			final SleepClosure param = BridgeUtilities.getFunction(args, script);
			final Stack argz = EventManager.shallowCopy(args);

			if (javax.swing.SwingUtilities.isEventDispatchThread()) {
				SleepUtils.runCode(param, "&dispatch_event", null, argz);
			}
			else {
				javax.swing.SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						SleepUtils.runCode(param, "&dispatch_event", null, argz);
					}
				});
			}
		}
		else if (name.equals("&apply")) {
			String temp = BridgeUtilities.getString(args, "");

			if (temp.length() == 0 || temp.charAt(0) != '&')
				throw new IllegalArgumentException(name + ": requested function name must begin with '&'");

			Function f = script.getScriptEnvironment().getFunction(temp);

			if (f == null)
				throw new RuntimeException("Function '" + temp + "' does not exist");

			/* build our arguments from our first argument */
			Stack argz = new Stack();

			Iterator i = BridgeUtilities.getIterator(args, script);
			while (i.hasNext()) {
				argz.add(0, i.next());
			}

			/* run the function and return the result */
			return SleepUtils.runCode(f, temp, script, argz);
		}
		return SleepUtils.getEmptyScalar();
	}
}
