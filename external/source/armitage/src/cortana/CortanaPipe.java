package cortana;

import java.io.*;
import java.util.*;

/* a pipe to receive output from Cortana and make it available in an event driven way to the user */
public class CortanaPipe implements Runnable {
	protected PipedInputStream readme;
	protected PipedOutputStream writeme;

	public OutputStream getOutput() {
		return writeme;
	}

	public CortanaPipe() {
		try {
			readme   = new PipedInputStream(1024 * 1024 * 1);
			writeme  = new PipedOutputStream(readme);
		}
		catch (IOException ioex) {
			ioex.printStackTrace();
		}
	}

	public interface CortanaPipeListener {
		public void read(String text);
	}

	protected List listeners = new LinkedList();

	public void addCortanaPipeListener(CortanaPipeListener l) {
		synchronized (this) {
			listeners.add(l);
		}

		if (listeners.size() == 1) {
			new Thread(this).start();
		}
	}

	public void run() {
		BufferedReader in = new BufferedReader(new InputStreamReader(readme));
		while (true) {
			try {
				String entry = in.readLine();
				if (entry != null) {
					synchronized (this) {
						Iterator i = listeners.iterator();
						while (i.hasNext()) {
							CortanaPipeListener l = (CortanaPipeListener)i.next();
							l.read(entry);
						}
					}
				}
			}
			catch (IOException ioex) {
				try {
					Thread.sleep(500);
				}
				catch (Exception ex) { }
				//ioex.printStackTrace();
			}
		}
	}
}
