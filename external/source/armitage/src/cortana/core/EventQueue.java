package cortana.core;

import java.util.*;
import sleep.runtime.*;

/* an event for firing events outside of the data management threads */
public class EventQueue implements Runnable {
	protected EventManager manager;
	protected LinkedList   queue = new LinkedList();

	private static class Event {
		public String name;
		public Stack args;
	}

	public EventQueue(EventManager manager) {
		this.manager = manager;
		new Thread(this).start();
	}

	public void add(String name, Stack args) {
		Event e = new Event();
		e.name = name;
		e.args = args;

		synchronized (this) {
			queue.add(e);
		}
	}

	protected Event grabEvent() {
		synchronized (this) {
			return (Event)queue.pollFirst();
		}
	}

	public void run() {
		while (true) {
			Event ev = grabEvent();

			try {
				if (ev != null) {
					manager.fireEvent(ev.name, ev.args, null);
				}
				else {
					Thread.sleep(25);
				}
			}
			catch (Exception ex) {
				if (ev != null)
					System.err.println(ev.name + " => " + SleepUtils.describe(ev.args));
				ex.printStackTrace();
			}
		}
	}
}
