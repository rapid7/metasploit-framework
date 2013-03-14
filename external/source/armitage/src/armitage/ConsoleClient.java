package armitage;

import console.Console;
import msf.*;
import java.util.*;
import java.util.regex.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/* A generic class to manage reading/writing to a console. Keeps the code simpler (although the Sleep code to do this is 
   simpler than this Java code. *sigh* */
public class ConsoleClient implements Runnable, ActionListener {
	protected RpcConnection connection;
	protected Console       window;
	protected String        readCommand;
	protected String        writeCommand;
	protected String        destroyCommand;
	protected String        session;
	protected LinkedList	listeners = new LinkedList();
	protected boolean       echo = true;
	protected boolean	go_read = true;
	protected ActionListener sessionListener = null; /* one off listener to catch "sessions -i ##" */

	public void setSessionListener(ActionListener l) {
		sessionListener = l;
	}

	public void kill() {
		synchronized (listeners) {
			go_read = false;
		}
	}

	public Console getWindow() {
		return window;
	}

	public void setEcho(boolean b) {
		echo = b;
	}

	public void setWindow(Console console) {
		synchronized (this) {
			window = console;
			setupListener();
		}
	}

	public void addSessionListener(ConsoleCallback l) {
		listeners.add(l);
	}

	public void fireSessionReadEvent(String text) {
		Iterator i = listeners.iterator();
		while (i.hasNext()) {
			((ConsoleCallback)i.next()).sessionRead(session, text);
		}
	}

	public void fireSessionWroteEvent(String text) {
		Iterator i = listeners.iterator();
		while (i.hasNext()) {
			((ConsoleCallback)i.next()).sessionWrote(session, text);
		}
	}

	public ConsoleClient(Console window, RpcConnection connection, String readCommand, String writeCommand, String destroyCommand, String session, boolean swallow) {
		this.window = window;
		this.connection = connection;
		this.readCommand = readCommand;
		this.writeCommand = writeCommand;
		this.destroyCommand = destroyCommand;
		this.session = session;

		setupListener();

		if (swallow) {
			try {
				readResponse();
			}
			catch (Exception ex) {
				System.err.println(ex);
			}
		}

		new Thread(this).start();
	}


	/* call this if the console client is referencing a metasploit console with tab completion */
	public void setMetasploitConsole() {
		window.addActionForKey("ctrl pressed Z", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				sendString("background\n");
			}
		});

		new TabCompletion(window, connection, session, "console.tabs");
	}

	/* called when the associated tab is closed */
	public void actionPerformed(ActionEvent ev) {
		if (destroyCommand != null) {
			((RpcAsync)connection).execute_async(destroyCommand, new Object[] { session });
		}

		/* we don't need to keep reading from this console */
		kill();
	}

	protected void finalize() {
		actionPerformed(null);
	}

	private static final Pattern interact = Pattern.compile("sessions -i (\\d+)\n");

	public void _sendString(String text) {
		if (writeCommand == null)
			return;

		/* intercept sessions -i and deliver it to a listener within armitage */
		if (sessionListener != null) {
			Matcher m = interact.matcher(text);
			if (m.matches()) {
				sessionListener.actionPerformed(new ActionEvent(this, 0, m.group(1)));
				return;
			}
		}

		Map read = null;

		try {
			synchronized (this) {
				if (window != null && echo) {
					window.append(window.getPromptText() + text);
				}
			}

			if ("armitage.push".equals(writeCommand)) {
				read = (Map)connection.execute(writeCommand, new Object[] { session, text });
			}
			else {
				connection.execute(writeCommand, new Object[] { session, text });
				read = readResponse();
			}
			processRead(read);

			fireSessionWroteEvent(text);
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	protected void setupListener() {
		synchronized (this) {
			if (window != null) {
				window.getInput().addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent ev) {
						final String text = window.getInput().getText() + "\n";
						window.getInput().setText("");
						sendString(text);
					}
				});
			}
		}
	}

	public static String cleanText(String text) {
		StringBuffer string = new StringBuffer(text.length());
		char chars[] = text.toCharArray();
		for (int x = 0; x < chars.length; x++) {
			if (chars[x] != 1 && chars[x] != 2)
				string.append(chars[x]);
		}

		return string.toString();
	}

	private Map readResponse() throws Exception {
		return (Map)(connection.execute(readCommand, new Object[] { session }));
	}

	private long lastRead = 0L;

	private void processRead(Map read) throws Exception {
		if (! "".equals( read.get("data") )) {
			String text = read.get("data") + "";

			synchronized (this) {
				if (window != null)
					window.append(text);
			}
			fireSessionReadEvent(text);
			lastRead = System.currentTimeMillis();
		}

		synchronized (this) {
			if (! "".equals( read.get("prompt") ) && window != null) {
				window.updatePrompt(cleanText(read.get("prompt") + ""));
			}
		}
	}

	protected LinkedList commands = new LinkedList();

	public void sendString(String text) {
		synchronized (listeners) {
			commands.add(text);
		}
	}

	public void run() {
		Map read;
		boolean shouldRead = go_read;
		String command = null;
		long last = 0;

		try {
			while (shouldRead) {
				synchronized (listeners) {
					if (commands.size() > 0) {
						command = (String)commands.removeFirst();
					}
				}

				if (command != null) {
					_sendString(command);
					command = null;
					lastRead = System.currentTimeMillis();
				}

				long now = System.currentTimeMillis();
				if (this.window != null && !this.window.isShowing() && (now - last) < 1500) {
					/* check if our window is not showing... if not, then we're going to switch to a very reduced
					   read schedule. */
				}
				else {
					read = readResponse();
					if (read == null || "failure".equals( read.get("result") + "" )) {
						break;
					}

					processRead(read);
					last = System.currentTimeMillis();
				}

				Thread.sleep(100);

				synchronized (listeners) {
					shouldRead = go_read;
				}
			}
		}
		catch (Exception javaSucksBecauseItMakesMeCatchEverythingFuckingThing) {
			javaSucksBecauseItMakesMeCatchEverythingFuckingThing.printStackTrace();
		}
	}
}
