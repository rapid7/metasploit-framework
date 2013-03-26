package cortana;

import msf.*;
import cortana.core.*;
import cortana.data.*;
import cortana.metasploit.*;
import cortana.support.*;
import cortana.gui.*;

import java.util.*;
import sleep.runtime.*;
import sleep.interfaces.*;
import sleep.error.*;
import sleep.bridges.io.*;
import java.io.*;

import java.text.*;

import armitage.*;

public class Cortana implements Loadable, RuntimeWarningWatcher {
	/** log all module launches and post-exploitation interaction */
	public static final int DEBUG_INTERACT_LOG = 256;

	/** ask for permission to launch a module or carry out a post-exploitation action */
	public static final int DEBUG_INTERACT_ASK = 512;

	protected RpcConnection  client;  /* connection to metasploit */
	protected RpcConnection  dserver; /* deconfliction server */

	protected ArmitageApplication application = null;
	protected Properties          preferences = null;
	protected Shared              shared      = null;

	protected EventManager   events;
	protected FilterManager  filters;
	protected CommandManager commands;
	protected DataManager    data;

	protected MetasploitBridge  metasploit;
	protected MeterpreterBridge meterpreter;
	protected ShellBridge       shell;
	protected ConsoleBridge     console;
	protected Loadable log   = null;
	protected Loadable locks = null;
	protected Loadable keys  = null;
	protected Loadable menus = null;
	protected Loadable ui    = null;
	protected Loadable utils = null;

	/* some stuff related to I/O */
	protected IOObject cortana_io = null;
	protected CortanaPipe pipe = null;

	/* a reference to the compiled version of our internal script, so we may reuse it */
	protected Object internal = null;
	protected Object internal_gui = null;
	protected Object internal_gui2 = null;

	protected boolean  started = false;

	public void scriptLoaded(ScriptInstance si) {
		if (cortana_io != null)
			IOObject.setConsole(si.getScriptEnvironment(), cortana_io);
	}

	/* setup a pointer to our armitage app. This will tell Cortana to start loading all
	   of the neat GUI stuff. */
	public void setupArmitage(ArmitageApplication application, Properties preferences) {
		/* a bridge for binding keyboard shortcuts */
		keys = new KeyBridge(application);

		/* a bridge for creating menus as needed */
		MenuBuilder builder = new MenuBuilder(application);
		application.setMenuBuilder(builder);

		menus = builder.getBridge();

		/* a bridge to assist with user-interface stuff */
		ui = new UIBridge(application);

		this.application = application;
		this.preferences = preferences;
		this.shared      = new Shared();
	}

	public void scriptUnloaded(ScriptInstance si) {
	}

	public Shared getSharedData() {
		return shared;
	}

	public Cortana(RpcConnection client, RpcConnection dserver, EventManager events, FilterManager filters) {
		this.client  = client;
		this.dserver = dserver;
		this.events  = events;
		this.filters = filters;

		/* this bridge provides the lowest abstraction on top of Metasploit */
		metasploit = new MetasploitBridge(client, dserver, events, filters);

		/* this bridge provides a low-level abstraction on top of Meterpreter */
		meterpreter = new MeterpreterBridge(client, dserver, events, filters);

		/* this bridge provides an abstraction on top of a shell session */
		shell = new ShellBridge(client, dserver, events, filters);

		/* this bridge provides each script with a Metasploit console to work with */
		console = new ConsoleBridge(client, events, filters);

		/* this bridge fires events from the Cortana event log */
		log = new EventLogBridge(client, dserver, events, filters);

		/* this bridge adds a mechanism for requesting a lock and freeing it after use */
		locks = new LockBridge(dserver, events);

		/* this bridge polls Metasploit periodically and keeps track of sessions, services, and hosts */
		data = new DataManager(dserver, events, client != dserver);

		/* this bridge contains some useful utilities that don't belong elsewhere */
		utils = new CortanaUtilities(metasploit);

		/* this bridge adds an environment tool that allows scripts to register commands. Commands may
		   be used in stand-alone Cortana or from the Cortana console in Armitage */
		commands = new CommandManager();
	}

	public void setupCallbackIO() {
		/* setup our pipe for uniform I/O? */
		pipe = new CortanaPipe();
		cortana_io = new IOObject();
		cortana_io.openWrite(pipe.getOutput());

		/* may as well jimmy the MetasploitBridge script count, so a quit() doesn't force us to exit
		   if this function is being called, we're definitely running in Armitage */
		metasploit.loadedScripts += 1;
	}

	public void addTextListener(CortanaPipe.CortanaPipeListener l) {
		pipe.addCortanaPipeListener(l);
	}

	private void p(String text) {
		if (cortana_io != null) {
			cortana_io.printLine(text);
		}
		else {
			System.out.println(text);
		}
	}

	public void processScriptWarning(ScriptWarning warning) {
		String from = warning.getNameShort() + ":" + warning.getLineNumber();

		SimpleDateFormat format = new SimpleDateFormat("HH:mm:ss");
		Date             adate  = new Date();
		String           niced  = format.format(adate, new StringBuffer(), new FieldPosition(0)).toString();

		if (warning.isDebugTrace()) {
			p("[" + niced + "] Trace: " + warning.getMessage() + " at " + from);
		}
		else {
			p("[" + niced + "] " + warning.getMessage() + " at " + from);
		}
	}

	public void filterList(List l, String filter) {
		Iterator i = l.iterator();
		while (i.hasNext()) {
			String cmd = i.next() + "";
			if (!cmd.startsWith(filter)) {
				i.remove();
			}
		}
	}

	public String findScript(String script) {
		Iterator i = scripts.keySet().iterator();
		while (i.hasNext()) {
			String name = i.next().toString();
			File s = new File(name);
			if (script.equals(s.getName())) {
				return name;
			}
		}
		return null;
	}

	public List commandList(String filter) {
		String[] data = filter.trim().split("\\s+");

		if ("askon".equals(data[0]) ||
		    "askoff".equals(data[0]) ||
		    "logon".equals(data[0]) ||
		    "logoff".equals(data[0]) ||
		    "reload".equals(data[0]) ||
		    "pron".equals(data[0]) ||
		    "profile".equals(data[0]) ||
		    "proff".equals(data[0]) ||
		    "tron".equals(data[0]) ||
		    "unload".equals(data[0]) ||
		    "troff".equals(data[0])) {
			/* construct list of potential reload commands */
			List res = new LinkedList();
			Iterator i = scripts.keySet().iterator();
			while (i.hasNext()) {
				res.add(data[0] + " " + new File(i.next() + "").getName());
			}

			/* filter this list */
			filterList(res, filter);
			Collections.sort(res);
			return res;
		}
		else if ("load".equals(data[0]) && filter.length() > 5) {
			filter = filter.replace("~", System.getProperty("user.home"));

			/* construct list of potential reload commands */
			String file = filter.substring(5);
			File   temp = new File(file);
			if (!temp.exists() || !temp.isDirectory()) {
				temp = temp.getParentFile();
			}

			List res = new LinkedList();

			if (temp == null) {
				res.add(filter);
				return res;
			}

			File s[] = temp.listFiles();
			for (int x = 0; s != null && x < s.length; x++) {
				if (s[x].isDirectory() || s[x].getName().endsWith(".cna"))
					res.add(data[0] + " " + s[x].getAbsolutePath());
			}

			/* filter this list */
			filterList(res, filter);
			Collections.sort(res);
			return res;
		}
		else {
			List cmdl = commands.commandList(filter);
			cmdl.add("askon");
			cmdl.add("askoff");
			cmdl.add("help");
			cmdl.add("ls");
			cmdl.add("reload");
			cmdl.add("unload");
			cmdl.add("load");
			cmdl.add("logon");
			cmdl.add("logoff");
			cmdl.add("pron");
			cmdl.add("proff");
			cmdl.add("profile");
			cmdl.add("tron");
			cmdl.add("troff");
			Collections.sort(cmdl);
			filterList(cmdl, filter);
			return cmdl;
		}
	}

	/* process a Cortana command */
	public void processCommand(String text) {
		String[] data = text.trim().split("\\s+");

		Set states = new HashSet();
		states.add("tron");
		states.add("troff");
		states.add("profile");
		states.add("pron");
		states.add("proff");
		states.add("logon");
		states.add("logoff");
		states.add("askon");
		states.add("askoff");

		Set cmds = new HashSet();
		cmds.addAll(states);
		cmds.add("unload");
		cmds.add("load");
		cmds.add("reload");

		if ("ls".equals(text)) {
			p("");
			p("Scripts");
			p("-------");
			Iterator i = scripts.keySet().iterator();
			while (i.hasNext()) {
				String temp = (String)i.next();
				if (temp != null) {
					File script = new File(temp);
					p(script.getName());
				}
			}
			p("");
		}
		else if (cmds.contains(data[0]) && data.length != 2) {
			p("[-] Missing arguments");
		}
		else if (states.contains(data[0]) && data.length == 2) {
			String script = findScript(data[1]);
			if (script == null) {
				p("[-] Could not find '" + data[1] + "'");
			}
			else {
				Loader loader = (Loader)scripts.get(script);
				if ("askon".equals(data[0])) {
					p("[+] Prompting actions for '" + data[1] + "'");
					loader.setDebugLevel(Cortana.DEBUG_INTERACT_ASK);
				}
				else if ("askoff".equals(data[0])) {
					p("[+] Stopped prompts from '" + data[1] + "'");
					loader.unsetDebugLevel(Cortana.DEBUG_INTERACT_ASK);
				}
				else if ("logon".equals(data[0])) {
					p("[+] Logging '" + data[1] + "'");
					loader.setDebugLevel(Cortana.DEBUG_INTERACT_LOG);
				}
				else if ("logoff".equals(data[0])) {
					p("[+] Stopped log of '" + data[1] + "'");
					loader.unsetDebugLevel(Cortana.DEBUG_INTERACT_LOG);
				}
				else if ("tron".equals(data[0])) {
					p("[+] Tracing '" + data[1] + "'");
					loader.setDebugLevel(8);
				}
				else if ("troff".equals(data[0])) {
					p("[+] Stopped trace of '" + data[1] + "'");
					loader.unsetDebugLevel(8);
				}
				else if ("pron".equals(data[0])) {
					p("[+] Profiling '" + data[1] + "'");
					loader.setDebugLevel(24);
				}
				else if ("profile".equals(data[0]) || "proff".equals(data[0])) {
					if ("proff".equals(data[0])) {
						p("[+] Stopped profile of '" + data[1] + "'");
						loader.unsetDebugLevel(24);
					}
					p("");
					p("Profile " + data[1]);
					p("-------");
					loader.printProfile(cortana_io == null ? System.out : cortana_io.getOutputStream());
					p("");
				}
			}
		}
		else if ("unload".equals(data[0]) && data.length == 2) {
			String script = findScript(data[1]);
			if (script == null) {
				p("[-] Could not find '" + data[1] + "'");
			}
			else {
				p("[+] Unload " + script);
				unloadScript(script);
			}
		}
		else if ("load".equals(data[0]) && data.length == 2) {
			p("[+] Load " + data[1]);
			try {
				loadScript(data[1]);
			}
			catch (YourCodeSucksException yex) {
				p(yex.formatErrors());
			}
			catch (Exception ex) {
				p("[-] Could not load: " + ex.getMessage());
			}
		}
		else if ("reload".equals(data[0]) && data.length == 2) {
			String script = findScript(data[1]);
			if (script == null) {
				p("[-] Could not find '" + data[1] + "'");
			}
			else {
				p("[+] Reload " + script);
				try {
					unloadScript(script);
					loadScript(script);
				}
				catch (java.io.IOException ioex) {
					p("[-] Could not load: '" + data[1] + "' " + ioex.getMessage());
				}
				catch (YourCodeSucksException yex) {
					p(yex.formatErrors());
				}
			}
		}
		else if ("help".equals(text)) {
			p("");
			p("Commands");
			p("--------");
			Iterator i = commandList("").iterator();
			while (i.hasNext()) {
				p(i.next() + "");
			}
			p("");
		}
		else {
			if (!commands.fireCommand(data[0], text)) {
				p("[-] Command not found");
			}
		}
	}

	public ConsoleClient getEventLog(console.Console window) {
		return ((EventLogBridge)log).start(window);
	}

	public MeterpreterSession getSession(String sid) {
		return meterpreter.getSession(sid);
	}

	public void updateLocalHost(String lhost) {
		metasploit.setLocalHost(lhost);
	}

	public void start(String lhost) {
		if (!started) {
			metasploit.setLocalHost(lhost);

			/* start grabbing data */
			data.start();

			/* start the timer thread */
			new cortana.support.Heartbeat(events).start();
		}
		started = true;
	}

	protected Map scripts = new HashMap();

	/* frees the specified script */
	public void unloadScript(String file) {
		Loader loader = (Loader)scripts.get(file);
		if (loader == null)
			return;

		scripts.remove(file);
		loader.unload();
	}

	public void loadScript(String file) throws YourCodeSucksException, java.io.IOException {
		/* initialize our script loader */
		Loader loader = new Loader(this);

		/* check whether this script is already loaded or not */
		if (scripts.containsKey(file)) {
			throw new RuntimeException(file + " is already loaded");
		}

		/* install our other abstractions... */
		loader.getScriptLoader().addGlobalBridge(events.getBridge());
		loader.getScriptLoader().addGlobalBridge(filters.getBridge());
		loader.getScriptLoader().addGlobalBridge(commands.getBridge());
		loader.getScriptLoader().addGlobalBridge(data);
		loader.getScriptLoader().addGlobalBridge(metasploit);
		loader.getScriptLoader().addGlobalBridge(meterpreter);
		loader.getScriptLoader().addGlobalBridge(shell);
		loader.getScriptLoader().addGlobalBridge(console);
		loader.getScriptLoader().addGlobalBridge(locks);
		loader.getScriptLoader().addGlobalBridge(log);
		loader.getScriptLoader().addGlobalBridge(utils);
		loader.getScriptLoader().addGlobalBridge(this);

		if (keys != null)
			loader.getScriptLoader().addGlobalBridge(keys);

		if (menus != null)
			loader.getScriptLoader().addGlobalBridge(menus);

		if (ui != null)
			loader.getScriptLoader().addGlobalBridge(ui);

		if (shared != null)
			loader.getScriptLoader().addGlobalBridge(shared);

		/* install some variables globally */
		loader.setGlobal("$client", SleepUtils.getScalar(client));
		loader.setGlobal("$mclient", SleepUtils.getScalar(dserver));

		/* load and run internal stuff that is scripted (I tire of working in Java) */
		internal = loader.loadInternalScript("scripts-cortana/internal.sl", internal);

		/* load some GUI stuff */
		if (keys != null || menus != null) {
			loader.setGlobal("$armitage", SleepUtils.getScalar(application));
			loader.setGlobal("$preferences", SleepUtils.getScalar(preferences));
			loader.setGlobal("$shared", SleepUtils.getScalar(shared));
			internal_gui  = loader.loadInternalScript("scripts-cortana/internal-ui.sl", internal_gui);
			internal_gui2 = loader.loadInternalScript("scripts-cortana/internal-ui-support.sl", internal_gui2);
		}

		/* load a script... */
		final ScriptInstance script = loader.loadScript(file);

		/* put this into our map of scripts */
		scripts.put(file, loader);

		/* fire ready event if we're already synced. This is an important signal for
		   cortana scripts */
		new Thread(new Runnable() {
			public void run() {
				if (data.isReady()) {
					events.fireEvent("ready", new Stack(), script);
				}
			}
		}).start();
	}

	public Cortana(RpcConnection client, RpcConnection dserver, String[] scripts, String lhost) {
		this(client, dserver, new EventManager(), new FilterManager());

		for (int x = 0; x < scripts.length; x++) {
			try {
				loadScript(scripts[x]);
			}
			catch (YourCodeSucksException yex) {
				System.err.println("Syntax errors in: " + scripts[x]);
				yex.printErrors(System.out);
			}
			catch (java.io.IOException ioex) {
				System.err.println("Could not load: " + scripts[x] + " " + ioex.getMessage());
				ioex.printStackTrace();
			}
		}

		/* start now that our scripts are loaded */
		((EventLogBridge)log).start(null);
		start(lhost);
	}
}
