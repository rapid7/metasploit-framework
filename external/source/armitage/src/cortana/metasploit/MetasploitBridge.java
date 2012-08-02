package cortana.metasploit;

import cortana.core.*;
import cortana.Safety;
import msf.*;
import armitage.ConsoleQueue;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

public class MetasploitBridge implements Loadable, Function, Predicate {
	protected EventManager  events;
	protected FilterManager filters;
	protected RpcConnection client;
	protected RpcConnection dserver;
	protected String        LHOST   = "";

	public int loadedScripts = 0;

	public void setLocalHost(String host) {
		LHOST = host;
	}

	public MetasploitBridge(RpcConnection client, RpcConnection dserver, EventManager events, FilterManager filters) {
		this.client  = client;
		this.dserver = dserver;
		this.events  = events;
		this.filters = filters;
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&lhost")) {
			return SleepUtils.getScalar(LHOST);
		}
		else if (name.equals("&quit")) {

			/* kill any active msfconsole session held by the script */
			if (script.getMetadata().containsKey("%msfconsole%")) {
				ConsoleQueue session = (ConsoleQueue)script.getMetadata().get("%msfconsole%");
				session.stop();
			}

			/* decrement our loaded scripts */
			synchronized (this) {
				loadedScripts -= 1;
				if (loadedScripts == 0) {
					System.exit(0);
				}
				else {
					script.setUnloaded();
				}
			}
			return SleepUtils.getEmptyScalar();
		}

		if (args.isEmpty()) {
			throw new IllegalArgumentException("missing arguments for " + name);
		}

		if (name.equals("&call") || name.equals("&call_async")) {
			/* args: call("db.call", arg1, arg2, arg3, ...) */
			String method = BridgeUtilities.getString(args, "");
			try {
				RpcConnection victim;
				if (method.startsWith("db.") || method.startsWith("armitage."))
					victim = dserver;
				else
					victim = client;

				/* safety features */
				if (Safety.shouldAsk(script)) {
					StringBuffer description = new StringBuffer();
					description.append("<html><body><b>");
					description.append(new java.io.File(script.getName()).getName());
					description.append("</b> wants to call <b>");
					description.append(method);

					if (!args.isEmpty()) {
						description.append("</b> with:</html></body>\n\n<html><body><b>");

						LinkedList l = new LinkedList(args);
						Collections.reverse(l);
						Iterator i = l.iterator();
						while (i.hasNext()) {
							String arg = SleepUtils.describe((Scalar)i.next());
							description.append(arg);
							if (i.hasNext())
								description.append("<br />");
						}
					}

					description.append("</b></body></html>\n\nWould you like to allow this?");

					if (!Safety.ask(script, description.toString(), "metasploit " + method + "(" + SleepUtils.describe(args) + ")")) {
						return SleepUtils.getHashScalar();
					}
				}

				if (Safety.shouldLog(script)) {
					Safety.log(script, "metasploit " + method + "(" + SleepUtils.describe(args) + ")");
				}

				/* launch the call */
				if (args.isEmpty()) {
					if (name.equals("&call")) {
						return FilterManager.convertAll(victim.execute(method));
					}
					else {
						((Async)victim).execute_async(method);
						return SleepUtils.getEmptyScalar();
					}
				}
				else {
					Object[] arguments = new Object[args.size()];
					for (int x = 0; x < arguments.length; x++) {
						arguments[x] = ObjectUtilities.buildArgument(Object.class, (Scalar)args.pop(), script);
					}
					arguments = filters.filterData(method.replace(".", "_"), arguments);

					if (name.equals("&call")) {
						return FilterManager.convertAll(victim.execute(method, arguments));
					}
					else {
						((Async)victim).execute_async(method, arguments);
						return SleepUtils.getEmptyScalar();
					}
				}
			}
			catch (IOException ioex) {
				throw new RuntimeException(ioex);
			}
		}
		return SleepUtils.getEmptyScalar();
	}

	public boolean decide(String predicate, ScriptInstance script, Stack terms) {
		String addr = BridgeUtilities.getString(terms, "");
		try {
			Object inet = java.net.InetAddress.getByName(addr);
			return (inet instanceof java.net.Inet6Address);
		}
		catch (Exception ex) {
			return false;
		}
	}

	public void scriptLoaded(ScriptInstance si) {
		si.getScriptEnvironment().getEnvironment().put("&call", this);
		si.getScriptEnvironment().getEnvironment().put("&call_async", this);
		si.getScriptEnvironment().getEnvironment().put("&quit", this);
		si.getScriptEnvironment().getEnvironment().put("&lhost", this);
		si.getScriptEnvironment().getEnvironment().put("-isipv6", this);

		synchronized (this) {
			loadedScripts++;
		}
	}

	public void scriptUnloaded(ScriptInstance si) {
	}
}
