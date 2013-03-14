package cortana.support;

import cortana.core.*;
import cortana.*;

import java.util.*;

/* a thread to keep track of different timer events and fire them off when it's appropriate */
public class Heartbeat implements Runnable {
	protected EventManager events;
	protected List         beats;

	private class Beat {
		protected long next = 0L;
		protected long mark;
		protected String event;

		public Beat(String event, long mark) {
			this.mark = mark;
			this.event = event;
			next = System.currentTimeMillis() + mark;
		}

		public void check(long now) {
			if (next <= now) {
				next = System.currentTimeMillis() + mark;
				events.fireEvent(event, new Stack());
			}
		}
	}

	public Heartbeat(EventManager e) {
		events = e;
		beats = new LinkedList();
		beats.add(new Beat("heartbeat_1s", 1 * 1000));
		beats.add(new Beat("heartbeat_5s", 5 * 1000));
		beats.add(new Beat("heartbeat_10s", 10 * 1000));
		beats.add(new Beat("heartbeat_15s", 15 * 1000));
		beats.add(new Beat("heartbeat_30s", 30 * 1000));
		beats.add(new Beat("heartbeat_1m",  60 * 1000));
		beats.add(new Beat("heartbeat_5m",  5 * 60 * 1000));
		beats.add(new Beat("heartbeat_10m", 10 * 60 * 1000));
		beats.add(new Beat("heartbeat_15m", 15 * 60 * 1000));
		beats.add(new Beat("heartbeat_20m", 20 * 60 * 1000));
		beats.add(new Beat("heartbeat_30m", 30 * 60 * 1000));
		beats.add(new Beat("heartbeat_60m", 60 * 60 * 1000));
	}

	public void start() {
		new Thread(this).start();
	}

	public void run() {
		while (true) {
			try {
				long now = System.currentTimeMillis();
				Iterator i = beats.iterator();
				while (i.hasNext()) {
					Beat temp = (Beat)i.next();
					temp.check(now);
				}
				Thread.sleep(1000);
			}
			catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}
}
