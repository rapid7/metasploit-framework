package cortana.data;

import cortana.core.*;

import armitage.*;

import graph.Route;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

import msf.*;

/* Poll metasploit, process certain data structures, fire events when those data structures change, and make this data
   available (in a base way) to Sleep scripts. The rest of the Data API will build on these primitives in Sleep. */
public class DataManager implements ArmitageTimerClient, Loadable, Function, Predicate {
	protected RpcConnection  client;
	protected EventManager   manager;

	protected Hosts          hosts;
	protected Routes         routes;
	protected Sessions       sessions;
	protected Services       services;
	protected Credentials    creds;
	protected Loots		 loots;

	protected boolean	 synced  = false;
	protected boolean        reset   = false;
	protected boolean        dserver = true;

	public DataManager(RpcConnection client, EventManager manager, boolean hasTeamServer) {
		this.client  = client;
		this.manager = manager;

		hosts    = new Hosts(client, manager);
		routes   = new Routes(client, manager);
		services = new Services(hosts, client, manager);
		sessions = new Sessions(hosts, client, manager);
		creds    = new Credentials(client, manager);
		loots    = new Loots(client, manager);
		dserver  = hasTeamServer;
	}

	public void start() {
		/* start three threads to periodically grab this information */
		Object[] arguments = new Object[] { new HashMap() };

		new CortanaTimer(client, "db.hosts", (long)(2.5 * 1000), this, dserver);
		new CortanaTimer(client, "db.services", 10  * 1000, this, dserver);
		new CortanaTimer(client, "db.creds", 30  * 1000, this, dserver);
		new CortanaTimer(client, "db.loots", 30  * 1000, this, dserver);
		new CortanaTimer(client, "session.list", 2 * 1000, this, dserver);
	}

	public boolean isReady() {
		synchronized (this) {
			return synced && !hosts.isInitial() && !services.isInitial() && !routes.isInitial() && !sessions.isInitial() && !creds.isInitial() && !loots.isInitial();
		}
	}

	public boolean result(String command, Object[] arguments, Map results) {
		synchronized (this) {
			if (command.equals("session.list")) {
				sessions.processSessions(results);
				routes.processRoutes(results);
			}
			else if (command.equals("db.services")) {
				services.processServices(results);
			}
			else if (command.equals("db.hosts")) {
				hosts.processHosts(results);
			}
			else if (command.equals("db.creds")) {
				creds.processCreds(results);
			}
			else if (command.equals("db.loots")) {
				loots.processLoots(results);
			}

			if (!synced) {
				if (!hosts.isInitial() && !services.isInitial() && !routes.isInitial() && !sessions.isInitial() && !creds.isInitial() && !loots.isInitial()) {
					boolean r = reset;

					synced = true;
					reset  = false;

					if (!r)
						manager.fireEventAsync("ready", new Stack());
					else
						manager.fireEventAsync("workspace_change", new Stack());
				}
			}

			return true;
		}
	}

        public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		synchronized (this) {
			if (name.equals("&sessions")) {
				return sessions.getScalar();
			}
			else if (name.equals("&hosts")) {
				return hosts.getScalar();
			}
			else if (name.equals("&credentials")) {
				return creds.getScalar();
			}
			else if (name.equals("&loots")) {
				return loots.getScalar();
			}
			else if (name.equals("&services")) {
				return services.getScalar();
			}
			else if (name.equals("&db_sync")) {
				Object[] arguments = new Object[] { new HashMap() };

				new CortanaTimer(client, "db.hosts", 0L, this, false);
				new CortanaTimer(client, "db.services", 0L, this, false);
				new CortanaTimer(client, "db.creds", 0L, this, false);

				return SleepUtils.getEmptyScalar();
			}
			else if (name.equals("&routes")) {
				return routes.getScalar();
			}
			else if (name.equals("&db_workspace")) {
				try {
					Map workspace = new HashMap();
					Object[] argz = new Object[1];

					if (args.size() >= 4) {
						String hosts   = BridgeUtilities.getString(args, "");
						String ports   = BridgeUtilities.getString(args, "");
						String os      = BridgeUtilities.getString(args, "");
						String session = BridgeUtilities.getString(args, "");

						if (!args.isEmpty()) {
							String size = BridgeUtilities.getString(args, "512");
							workspace.put("size", size);
						}

						if (!hosts.equals(""))
							workspace.put("hosts", hosts);

						if (!ports.equals(""))
							workspace.put("ports", ports);

						if (!os.equals(""))
							workspace.put("os", os);

						if (!session.equals(""))
							workspace.put("session", "1");

						argz[0] = workspace;
					}
					else if (args.size() == 1) {
						argz[0] = SleepUtils.getMapFromHash((Scalar)args.pop());
						if (!(argz[0] instanceof Map))
							throw new IllegalArgumentException("&db_workspace requires a hash");
					}
					else {
						/* this will reset the filter */
						argz[0] = new HashMap();
					}

					client.execute("db.filter", argz);
					reset = true;
					synced = false;
					hosts.reset();
					sessions.reset();
					routes.reset();
					services.reset();
					creds.reset();
				}
				catch (IOException ioex) {
					throw new RuntimeException(ioex);
				}
			}
		}
                return SleepUtils.getEmptyScalar();
        }

	public boolean decide(String predicate, ScriptInstance script, Stack terms) {
		synchronized (this) {
			if (predicate.equals("hasservice")) {
				String port = BridgeUtilities.getString(terms, "");
				String addr = BridgeUtilities.getString(terms, "");

				Host host = (Host)hosts.getHosts().get(addr);
				if (host != null) {
					return host.hasService(port);
				}
			}
			else if (predicate.equals("ispivot")) {
				String addr  = BridgeUtilities.getString(terms, "");
				String sid = BridgeUtilities.getString(terms, "");

				Iterator i = routes.getRoutes().iterator();
				while (i.hasNext()) {
					Route r = (Route)i.next();
					if (sid.equals(r.getGateway()) && r.shouldRoute(addr)) {
						return true;
					}
				}
			}
			else if (predicate.equals("isroute")) {
				String addr  = BridgeUtilities.getString(terms, "");
				Route route = (Route)BridgeUtilities.getObject(terms);

				return route.shouldRoute(addr);
			}
			else if (predicate.equals("-isready")) {
				String sid = BridgeUtilities.getString(terms, "");
				Map session = sessions.getSession(sid);
				if (session == null)
					return false;
				return !"meterpreter".equals(session.get("type")) || !"".equals(session.get("info"));
			}
			else if (predicate.equals("-ismeterpreter")) {
				String sid = BridgeUtilities.getString(terms, "");
				Map session = sessions.getSession(sid);
				if (session == null)
					return false;
				return "meterpreter".equals(session.get("type"));
			}
			else if (predicate.equals("-isshell")) {
				String sid = BridgeUtilities.getString(terms, "");
				Map session = sessions.getSession(sid);
				if (session == null)
					return false;
				return "shell".equals(session.get("type"));
			}
			else if (predicate.equals("-iswinmeterpreter")) {
				String sid = BridgeUtilities.getString(terms, "");
				Map session = sessions.getSession(sid);
				if (session == null)
					return false;
				return "meterpreter".equals(session.get("type")) && ("x86/win32".equals(session.get("platform")) || "x86/win64".equals(session.get("platform")));
			}
		}

		return false;
	}

        public void scriptLoaded(ScriptInstance script) {
                Hashtable env = script.getScriptEnvironment().getEnvironment();
		env.put("&credentials",      this);
		env.put("&loots",            this);
                env.put("&sessions",         this);
                env.put("&hosts",            this);
                env.put("&services",         this);
		env.put("&db_sync",          this);
                env.put("&routes",           this);
		env.put("&db_workspace",     this);
		env.put("hasservice",        this);
		env.put("ispivot",           this);
		env.put("isroute",           this);
		env.put("-isshell",          this);
		env.put("-ismeterpreter",    this);
		env.put("-iswinmeterpreter", this);
		env.put("-isready",          this);
		env.put("ispivot",           this);
        }

        public void scriptUnloaded(ScriptInstance script) {
        }
}
