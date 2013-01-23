/* Cortana Scripting Language
 * --------------------------
 * Author: Raphael Mudge (raffi@strategiccyber.com)
 *
 * Funded by DARPA's Cyber Fast Track Program (jEAH bABY)
 */
package cortana;

import msf.*;

import java.util.*;
import java.io.*;

import sleep.runtime.SleepUtils;
import sleep.error.*;

public class Main implements Runnable, CortanaPipe.CortanaPipeListener {
	/* setup a script loader, install the RPC connection as a global var, and load several Armitage
	   scripts to help stage the database so we can pull data from it. This is a whacky way to do it, but...
	   as Armitage changes, Cortana will keep up, and this allows me to make design decisions that will
	   make it easier to add Cortana to Armitage later. I'm not completely crazy. */
	public static Object[] setupConnections(String host, String port, String user, String pass, String nick) {
		Loader loader = new Loader(new RuntimeWarningWatcher() {
			public void processScriptWarning(ScriptWarning warning) {
				System.err.println(warning);
			}
		});
		loader.setGlobal("$loader", SleepUtils.getScalar(loader));
		loader.setGlobal("$host",   SleepUtils.getScalar(host));
		loader.setGlobal("$port",   SleepUtils.getScalar(port));
		loader.setGlobal("$user",   SleepUtils.getScalar(user));
		loader.setGlobal("$pass",   SleepUtils.getScalar(pass));
		loader.setGlobal("$nick",   SleepUtils.getScalar(nick));
		loader.loadInternalScript("scripts/util.sl", null);
		loader.loadInternalScript("scripts/jobs.sl", null);
                loader.loadInternalScript("scripts/preferences.sl", null);
		loader.loadInternalScript("scripts-cortana/cortanadb.sl", null);

		/* we're waiting for some async actions in these scripts to complete before we
		  turn our execution to the cortana scripts that exist in this container. */
		while (!loader.isReady()) {
			try {
				Thread.sleep(10);
			}
			catch (Exception ex) {
				// do nothing...
			}
		}
		return loader.getPassedObjects();
	}

	protected Cortana engine = null;

	public void run() {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		while (true) {
			try {
				String entry = in.readLine();
				if (entry != null && !"".equals(entry))
					engine.processCommand(entry);
			}
			catch (IOException ioex) {
			}
		}
	}

	public void start(String host, String port, String user, String pass, String nick, String[] scripts) {
		/* rock 'n' roll with this big bad puff o stuff */
		try {
			Object conns[] = setupConnections(host, port, user, pass, nick);
			//new MsgRpcImpl(user, pass, host, Integer.parseInt(port), true, false);
			engine = new Cortana((RpcConnection)conns[0], (RpcConnection)conns[1], scripts, (String)conns[2]);
			new Thread(this).start();
		}
		catch (java.lang.RuntimeException rex) {
			if (rex.getCause() != null)
				System.err.println(rex.getCause().getMessage());
			else
				rex.printStackTrace();
			System.exit(1);
		}
	}

	public void read(String text) {
		System.out.println(text);
	}

	public static void main(String args[]) {
		msf.MeterpreterSession.DEFAULT_WAIT = 20000L;

		if (args.length >= 1) {
			try {
				/* load our properties file */
				Properties temp = new Properties();
				temp.load(new FileInputStream(args[0]));
				String argz[] = new String[5];
				argz[0] = temp.getProperty("host");
				argz[1] = temp.getProperty("port");
				argz[2] = temp.getProperty("user");
				argz[3] = temp.getProperty("pass");
				argz[4] = temp.getProperty("nick");

				/* ok, now get our scripts from this mess too */
				String scripts[] = new String[args.length - 1];
				for (int x = 1; x < args.length; x++) {
					scripts[x - 1] = args[x];
				}

				Main cortanaEngine = new Main();
				cortanaEngine.start(argz[0], argz[1], argz[2], argz[3], argz[4], scripts);
			}
			catch (IOException ex) {
				System.err.println(ex.getMessage());
				System.exit(1);
			}
			return;
		}
		else {
			showHelp();
		}
	}

	public static void showHelp() {
		System.err.println("java -jar cortana.jar [connection.prop] [script] ... [script n]\n");
		System.err.println("\tCortana is a client for the Metasploit framework. You");
		System.err.println("\tmust provide the details to connect to a running Metasploit");
		System.err.println("\tinstance.");
	}
}
