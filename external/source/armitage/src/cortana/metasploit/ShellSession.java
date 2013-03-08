package cortana.metasploit;

import java.util.*;
import java.awt.*;
import java.awt.event.*;

import msf.*;
import java.math.*;
import java.security.*;

/* Implements a class for writing commands to a shell and firing an
   event when the command is successfully executed (with its output) */
public class ShellSession implements Runnable {
	protected RpcConnection connection;
	protected RpcConnection dserver;
	protected LinkedList    listeners = new LinkedList();
	protected LinkedList    commands  = new LinkedList();
	protected String        session;

	private static class Command {
		public Object   token;
		public String   text;
		public long	start = System.currentTimeMillis();
	}

	public static interface ShellCallback {
		public void commandComplete(String session, Object token, String response);
		public void commandUpdate(String session, Object token, String response);
	}

	public void addListener(ShellCallback l) {
		synchronized (this) {
			listeners.add(l);
		}
	}

	public void fireEvent(Command command, String output, boolean done) {
		Iterator i;
		synchronized (this) {
			i = new LinkedList(listeners).iterator();
		}

		while (i.hasNext()) {
			if (done)
				((ShellCallback)i.next()).commandComplete(session, command != null ? command.token : null, output);
			else
				((ShellCallback)i.next()).commandUpdate(session, command != null ? command.token : null, output);
		}
	}

	public ShellSession(RpcConnection connection, RpcConnection dserver, String session) {
		this.connection = connection;
		this.dserver    = dserver;
		this.session = session;
		new Thread(this).start();
	}

	private SecureRandom random = new SecureRandom();

	protected void processCommand(Command c) {
		Map response = null, read = null;
		try {
			String marker = new BigInteger(130, random).toString(32) + "\n";

			StringBuffer writeme = new StringBuffer();
			writeme.append(c.text);
			writeme.append("\n");
			writeme.append("echo " + marker);

			/* write our command to whateverz */
			connection.execute("session.shell_write", new Object[] { session, writeme.toString() });

			/* read until we encounter AAAAAAAAAA */
			StringBuffer output = new StringBuffer();

			/* loop forever waiting for response to come back. If session is dead
			   then this loop will break with an exception */
			long start = System.currentTimeMillis();
			while ((System.currentTimeMillis() - start) < 60000) {
				response = readResponse();
				String data = (response.get("data") + "");

				if (data.length() > 0) {
					if (data.endsWith(marker)) {
						data = data.substring(0, data.length() - marker.length());
						fireEvent(c, data, false);
						output.append(data);
						fireEvent(c, output.toString(), true);
						return;
					}
					else {
						fireEvent(c, data, false);
						output.append(data);
					}
				}

				Thread.sleep(100);
			}
			System.err.println(session + " -> " + c.text + " (took longer than anticipated, dropping: " + (System.currentTimeMillis() - start) + ")");
		}
		catch (Exception ex) {
			System.err.println(session + " -> " + c.text + " ( " + response + ")");
			ex.printStackTrace();
		}
	}

	public void addCommand(Object token, String text) {
		synchronized (this) {
			if (text.trim().equals("")) {
				return;
			}
			Command temp = new Command();
			temp.token = token;
			temp.text  = text;
			commands.add(temp);
		}
	}

	protected Command grabCommand() {
		synchronized (this) {
			return (Command)commands.pollFirst();
		}
	}

	/* try to acquire a lock on the shell or loop forever */
	public void acquireLock() {
		while (true) {
			try {
				Map temp = (Map)dserver.execute("armitage.lock", new Object[] { session, "Cortana" });
				if (!temp.containsKey("error"))
					return;

				Thread.sleep(500);
			}
			catch (Exception ex) {
			}
		}
	}

	/* keep grabbing commands, acquiring locks, until everything is executed */
	public void run() {
		boolean needLock = true;

		while (true) {
			try {
				Command next = grabCommand();
				if (next != null) {
					if (needLock) {
						acquireLock();
						needLock = false;
					}

					processCommand(next);
					Thread.sleep(50);
				}
				else {
					if (!needLock) {
						dserver.execute("armitage.unlock", new Object[] { session });
						needLock = true;
					}
					Thread.sleep(500);
				}
			}
			catch (Exception ex) {
				System.err.println("This session appears to be dead! " + session + ", " + ex);
				return;
			}
		}
	}

	private Map readResponse() throws Exception {
		return (Map)(connection.execute("session.shell_read", new Object[] { session }));
	}
}
