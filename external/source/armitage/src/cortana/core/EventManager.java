package cortana.core;

import java.util.*;
import sleep.runtime.*;
import sleep.bridges.*;
import sleep.interfaces.*;

public class EventManager {
	protected Map listeners;
	protected EventQueue queue;

	protected List getListener(String name) {
		if (listeners.containsKey(name)) {
			return (List)listeners.get(name);
		}
		else {
			listeners.put(name, new LinkedList());
			return (List)listeners.get(name);
		}
	}

	public Loadable getBridge() {
		return new Events(this);
	}

	public EventManager() {
		listeners = new HashMap();
		queue     = new EventQueue(this);
	}

	private static class Listener {
		protected SleepClosure listener;
		protected boolean      temporary;

		public Listener(SleepClosure listener, boolean temporary) {
			this.listener  = listener;
			this.temporary = temporary;
		}

		public SleepClosure getClosure() {
			return listener;
		}

		public boolean isTemporary() {
			return temporary;
		}
	}

	public void addListener(String listener, SleepClosure c, boolean temporary) {
		getListener(listener).add(new Listener(c, temporary));
	}

	public static Stack shallowCopy(Stack args) {
		Stack copy = new Stack();
		Iterator i = args.iterator();
		while (i.hasNext()) {
			copy.push(i.next());
		}
		return copy;
	}

	public void fireEvent(String eventName, Stack args) {
		fireEvent(eventName, args, null);
	}

	public void fireEventAsync(String eventName, Stack args) {
		queue.add(eventName, args);
	}

	public void fireEvent(String eventName, Stack args, ScriptInstance local) {
		List listeners = getListener(eventName);
		if (listeners.size() == 0)
			return;

		Iterator i = listeners.iterator();

		List callme = new LinkedList();
		Object lid = null;

		if (local != null)
			lid = local.getMetadata().get("%scriptid%");

		while (i.hasNext()) {
			Listener l = (Listener)i.next();
			if (!l.getClosure().getOwner().isLoaded()) {
				/* remove scripts that have quit() on us */
				i.remove();
			}
			else if (lid == null || lid.equals(l.getClosure().getOwner().getMetadata().get("%scriptid%"))) {
				callme.add(l.getClosure());

				if (l.isTemporary())
					i.remove();
			}
		}

		i = callme.iterator();
		while (i.hasNext()) {
			SleepClosure c = (SleepClosure)i.next();
			SleepUtils.runCode(c, eventName, null, shallowCopy(args));
		}
	}
}
