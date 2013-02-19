package cortana;

import cortana.core.*;

import sleep.runtime.*;
import sleep.interfaces.*;

import sleep.error.*;

import java.io.*;
import java.util.*;

/** The Loader creates an isolated script instance for each Cortana script that we load */
public class Loader implements Loadable {
	protected ScriptLoader    loader;
	protected Hashtable       shared  = new Hashtable();
	protected ScriptVariables vars    = new ScriptVariables();
	protected Object[]        passMe  = new Object[3];
	protected List		  scripts = new LinkedList();

	public void unsetDebugLevel(int flag) {
		Iterator i = scripts.iterator();
		while (i.hasNext()) {
			ScriptInstance script = (ScriptInstance)i.next();
			int flags = script.getDebugFlags() & ~flag;
			script.setDebugFlags(flags);
		}
	}

	public void printProfile(OutputStream out) {
		Iterator i = scripts.iterator();
		while (i.hasNext()) {
			ScriptInstance script = (ScriptInstance)i.next();
			script.printProfileStatistics(out);
			return;
		}
	}

	public void setDebugLevel(int flag) {
		Iterator i = scripts.iterator();
		while (i.hasNext()) {
			ScriptInstance script = (ScriptInstance)i.next();
			int flags = script.getDebugFlags() | flag;
			script.setDebugFlags(flags);
		}
	}

	public boolean isReady() {
		synchronized (this) {
			return passMe != null;
		}
	}

	public void passObjects(Object o, Object p, Object q) {
		synchronized (this) {
			passMe[0] = o;
			passMe[1] = p;
			passMe[2] = q;
		}
	}

	public Object[] getPassedObjects() {
		synchronized (this) {
			return passMe;
		}
	}

	public void setGlobal(String name, Scalar value) {
		vars.getGlobalVariables().putScalar(name, value);
	}

	public ScriptLoader getScriptLoader() {
		return loader;
	}

	protected RuntimeWarningWatcher watcher;

	public Loader(RuntimeWarningWatcher watcher) {
		loader = new ScriptLoader();
		loader.addSpecificBridge(this);
		this.watcher = watcher;
	}

	public void scriptLoaded(ScriptInstance i) {
		i.setScriptVariables(vars);
		i.addWarningWatcher(watcher);
		scripts.add(i);

		/* store a hashcode in metadata so we have a unique way of marking
		   this script and its children forks */
		i.getMetadata().put("%scriptid%", i.hashCode());
	}

	public void unload() {
		Iterator i = scripts.iterator();
		while (i.hasNext()) {
			ScriptInstance temp = (ScriptInstance)i.next();
			temp.setUnloaded();
		}

		scripts = null;
		vars = null;
		shared = null;
		passMe = null;
		loader = null;
	}

	public void scriptUnloaded(ScriptInstance i) {

	}

	public Object loadInternalScript(String file, Object cache) {
		try {
			/* we cache the compiled version of internal scripts to conserve some memory */
			if (cache == null) {
				InputStream i = this.getClass().getClassLoader().getResourceAsStream(file);
				if (i == null)
					throw new RuntimeException("resource " + file + " does not exist");

				cache = loader.compileScript(file, i);
			}

			ScriptInstance script = loader.loadScript(file, (sleep.engine.Block)cache, shared);
			script.runScript();
		}
		catch (IOException ex) {
			System.err.println("*** Could not load: " + file + " - " + ex.getMessage());
		}
		catch (YourCodeSucksException ex) {
			ex.printErrors(System.out);
		}
		return cache;
	}

	public ScriptInstance loadScript(String file) throws IOException {
		setGlobal("$__script__", SleepUtils.getScalar(file));
		ScriptInstance script = loader.loadScript(file, shared);
		script.runScript();
		return script;
	}
}
