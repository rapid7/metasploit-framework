package armitage;

import console.Console;
import msf.*;
import java.util.*;

/** A generic class to execute several queries and return their results */
public class SimpleTimer implements Runnable {
	protected long                sleepPeriod;
	protected Runnable            doit;
	protected boolean             flag;

	public SimpleTimer(long period) {
		sleepPeriod = period;
		flag = true;
	}

	public void setRunnable(Runnable r) {
		doit = r;
		new Thread(this).start();
	}

	/* this should only be called within the thread executing the runnable */
	public void stop() {
		flag = false;
	}

	public void run() {
		try {
			while (flag) {
				doit.run();
				Thread.sleep(sleepPeriod);
			}
		}
		catch (Exception ex) {	
			System.err.println("TIMER DIED | continue: " + flag + ", " + sleepPeriod + "ms, " + doit);
			ex.printStackTrace();
		}
	}
}
