package cortana.support;

import cortana.core.*;
import cortana.*;

import java.util.*;

import sleep.runtime.*;
import sleep.interfaces.*;
import sleep.bridges.*;

import msf.*;

public class LockBridge implements Function, Loadable, Runnable {
	protected EventManager  events;
	protected RpcConnection connection;
	protected List          locks = new LinkedList();

	private class LockMinion {
		protected String name;
		protected ScriptInstance script;
		protected boolean keep;
		protected Stack         args;

		public LockMinion(String name, ScriptInstance script, boolean keep, Stack args) {
			this.name   = name;
			this.script = script;
			this.keep   = keep;
			this.args   = args;
		}

		public boolean grab() {
			if (acquireLock(name, script)) {
				events.fireEvent("locked_" + name, args, script);
				if (!keep)
					releaseLock(name);
				return true;
			}
			return false;
		}
	}

	public LockBridge(RpcConnection connection, EventManager events) {
		this.connection = connection;
		this.events     = events;
		new Thread(this).start();
	}

	public boolean acquireLock(String name, ScriptInstance script) {
		try {
			Map temp = (Map)connection.execute("armitage.lock", new Object[] { name, script.getName() });
			if (!temp.containsKey("error"))
				return true;
		}
		catch (Exception ex) {
		}
		return false;
	}

	public void releaseLock(String name) {
		try {
			((Async)connection).execute_async("armitage.unlock", new Object[] { name });
		}
		catch (Exception ex) {
		}
	}

	public void run() {
		while (true) {
			List templ;
			synchronized (this) {
				templ = new LinkedList(locks);
			}

			try {
				if (templ.size() == 0) {
					Thread.sleep(2000);
				}
				else {
					List tempr = new LinkedList();

					/* loop through our locks (in order) and try to acquire them and release them */
					Iterator i = templ.iterator();
					while (i.hasNext()) {
						LockMinion m = (LockMinion)i.next();
						if (m.grab())
							tempr.add(m);
						Thread.sleep(100);
					}

					/* now, take any locks that were successful and remove them from oust list */
					synchronized (this) {
						i = tempr.iterator();
						while (i.hasNext()) {
							locks.remove(i.next());
						}
					}

					/* now, sleep... */
					Thread.sleep(1000);
				}
			}
			catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		String lname = BridgeUtilities.getString(args, "");
		if (name.equals("&lock")) {
			Scalar last = BridgeUtilities.getScalar(args);
			synchronized (this) {
				locks.add( new LockMinion( lname, script, SleepUtils.isTrueScalar(last), (Stack)args.clone() ) );
			}
		}
		else {
			releaseLock(lname);
		}
		return SleepUtils.getEmptyScalar();
	}

	public void scriptLoaded(ScriptInstance script) {
		script.getScriptEnvironment().getEnvironment().put("&lock", this);
		script.getScriptEnvironment().getEnvironment().put("&unlock", this);
	}

	public void scriptUnloaded(ScriptInstance script) {
	}
}
