package armitage;

import console.*;

import java.util.*;
import java.awt.*;
import java.awt.event.*;

import msf.*;
import java.math.*;
import java.security.*;

/* Implements a class for writing commands to a console and firing an event when the command is successfully executed
   (with its output). My hope is that this will replace the CommandClient class which likes to execute stuff out of order */
public class ConsoleQueue implements Runnable {
	protected RpcConnection connection;
	protected LinkedList    listeners = new LinkedList();
	protected LinkedList    listeners_all = new LinkedList();
	protected LinkedList    commands  = new LinkedList();
	protected String        consoleid   = null;
	protected Console display = null;

	private static class Command {
		public Object   token  = null;
		public String   text   = null;
		public Map      assign = null;
		public long	start = System.currentTimeMillis();
	}

	public Console getWindow() {
		return display;
	}

	public static interface ConsoleCallback {
		public void commandComplete(ConsoleQueue queue, Object token, String response);
	}

	/* I'm not necessarily trying to bloat this class, but this method will let me get rid of another class */
	public java.util.List tabComplete(String pcommand) {
		try {
			Map read = (Map)connection.execute("console.tabs", new Object[] { consoleid, pcommand });
			if (read.containsKey("tabs")) {
				return (java.util.List)read.get("tabs");
			}
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
		return new LinkedList();
	}

	public void addListener(ConsoleCallback l) {
		listeners.add(l);
	}

	public void addSessionListener(ConsoleCallback l) {
		listeners_all.add(l);
	}

	public void setDisplay(final Console display) {
		this.display = display;
		display.getInput().addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				display.getInput().setText("");
				addCommand(null, ev.getActionCommand());
			}
		});
	}

	public void fireSessionReadEvent(String text) {
		Iterator i = listeners_all.iterator();
		while (i.hasNext()) {
			((ConsoleCallback)i.next()).commandComplete(this, null, text);
		}
	}

	public void fireEvent(Command command, String output) {
		if (command.token == null)
			return;

		Iterator i = listeners.iterator();
		while (i.hasNext()) {
			((ConsoleCallback)i.next()).commandComplete(this, command != null ? command.token : null, output);
		}
	}

	public ConsoleQueue(RpcConnection connection) {
		this.connection = connection;
	}

	public boolean isEmptyData(String data) {
		return "".equals(data) || "null".equals(data);
	}

	protected void processCommand(Command c) {
		if (c.assign == null) {
			processNormalCommand(c);
		}
		else {
			processAssignCommand(c);
		}
	}

	protected void processAssignCommand(Command c) {
		try {
			/* absorb anything misc */
			Map read = readResponse();
			String prompt = ConsoleClient.cleanText(read.get("prompt") + "");

			StringBuffer writeme = new StringBuffer();
			Set expected = new HashSet();

			/* loop through our values to assign */
			Iterator i = c.assign.entrySet().iterator();
			while (i.hasNext()) {
				Map.Entry entry = (Map.Entry)i.next();
				String key = entry.getKey() + "";
				String value = entry.getValue() + "";
				writeme.append("set " + key + " " + value + "\n");
				expected.add(key);
			}

			/* write our command to whateverz */
			connection.execute("console.write", new Object[] { consoleid, writeme.toString() });

			long start = System.currentTimeMillis();

			/* process through all of our values */
			while (expected.size() > 0) {
				Thread.yield();
				Map temp = (Map)(connection.execute("console.read", new Object[] { consoleid }));
				if (!isEmptyData(temp.get("data") + "")) {
					String[] lines = (temp.get("data") + "").split("\n");
					for (int x = 0; x < lines.length; x++) {
						if (lines[x].indexOf(" => ") != -1) {
							String[] kv = lines[x].split(" => ");

							/* remove any set variables from our set of stuff */
							expected.remove(kv[0]);

							if (display != null) {
								display.append(prompt + "set " + kv[0] + " " + kv[1] + "\n");
								display.append(lines[x] + "\n");
							}
						}
						else if (display != null) {
							display.append(lines[x] + "\n");
						}
						else {
							System.err.println("Batch read unexpected: " + lines[x]);
						}
					}
				}
				else if ((System.currentTimeMillis() - start) > 10000) {
					/* this is a safety check to keep a console from spinning waiting for one command to complete. Shouldn't trigger--unless I mess up :) */
					System.err.println("Timed out: " + c.assign + " vs. " + expected);
					break;
				}
			}
		}
		catch (Exception ex) {
			System.err.println(consoleid + " -> " + c.text);
			ex.printStackTrace();
		}
	}

	protected void processNormalCommand(Command c) {
		Map read = null;
		try {
			if (c.text.startsWith("ECHO ")) {
				if (display != null) {
					display.append(c.text.substring(5));
				}
				return;
			}

			StringBuffer writeme = new StringBuffer();
			writeme.append(c.text);
			writeme.append("\n");

			/* absorb anything misc */
			read = readResponse();
			String prompt = ConsoleClient.cleanText(read.get("prompt") + "");

			/* print ze command y0 */
			if (display != null) {
				display.append(prompt + writeme.toString());
			}

			/* write our command to whateverz */
			connection.execute("console.write", new Object[] { consoleid, writeme.toString() });

			/* start collecting output */
			StringBuffer output = new StringBuffer();
			Thread.sleep(10);
			int count = 0;
			long start = System.currentTimeMillis();

			while ((read = readResponse()) != null) {
				String text = null;
				if (! isEmptyData( read.get("data") + "" )  ) {
					text = read.get("data") + "";
					output.append(text);
					count++;
				}
				else if ("false".equals( read.get("busy") + "" ) && isEmptyData( read.get("data") + "" )) {
					if (count > 0) {
						break;
					}
					else if ((System.currentTimeMillis() - start) > 10000) {
						/* this is a safety check to keep a console from spinning waiting for one command to complete. Shouldn't ever trigger. */
						System.err.println("Timed out: " + c.text);
						break;
					}
				}
				else if ("failure".equals( read.get("result") + "" )) {
					break;
				}

				if (!prompt.equals( ConsoleClient.cleanText(read.get("prompt") + "") )) {
					/* this is a state change, we'll count it */
					count++;
				}

				Thread.sleep(10);
			}

			/* fire an event with our output */
			fireEvent(c, output.toString());
		}
		catch (Exception ex) {
			System.err.println(consoleid + " -> " + c.text + " ( " + read + ")");
			ex.printStackTrace();
		}
	}

	public void append(String text) {
		addCommand(null, "ECHO " + text + "\n");
	}

	public void setOptions(Map options) {
		synchronized (this) {
			Command temp = new Command();
			temp.token  = null;
			temp.text   = null;
			temp.assign = options;
			commands.add(temp);
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

	protected boolean stop = false;

	public void start() {
		new Thread(this).start();
	}

	public void stop() {
		synchronized (this) {
			stop = true;
		}
	}

	public void destroy() {
		synchronized (this) {
			destroyCommand = "console.release_and_destroy";
			stop = true;
		}
	}

	protected Command grabCommand() {
		synchronized (this) {
			return (Command)commands.pollFirst();
		}
	}

	/* keep grabbing commands, acquiring locks, until everything is executed */
	public void run() {
		try {
			Map read = (Map)connection.execute("console.allocate", new Object[] {});
			consoleid = read.get("id") + "";

			while (true) {
				Command next = grabCommand();
				if (next != null) {
					processCommand(next);
					Thread.sleep(10);
				}
				else {
					synchronized (this) {
						if (stop) {
							break;
						}
					}

					if (display != null)
						readResponse();

					Thread.sleep(1000);
				}
			}

			connection.execute(destroyCommand, new Object[] { consoleid });
		}
		catch (Exception ex) {
			System.err.println("This console appears to be dead! " + consoleid + ", " + ex);
			return;
		}
	}

	private String destroyCommand = "console.release";

        private Map readResponse() throws Exception {
		Thread.yield();
		Map temp = (Map)(connection.execute("console.read", new Object[] { consoleid }));
		if (display != null && !isEmptyData(temp.get("data") + "")) {
			display.append(temp.get("data") + "");
			fireSessionReadEvent(temp.get("data") + "");
		}

		if (display != null && !isEmptyData(temp.get("prompt") + "")) {
			String prompt = ConsoleClient.cleanText(temp.get("prompt") + "");
			display.updatePrompt(prompt);
		}

		return temp;
        }
}
