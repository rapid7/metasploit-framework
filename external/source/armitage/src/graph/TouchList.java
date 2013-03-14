package graph;

import java.util.*;

/** A touch map lets me start an operation, "touch" each updated node, and then delete any untouched node */
public class TouchList extends LinkedList {
	protected Set touched = new HashSet();

	public void startUpdates() {
		touched.clear();
	}

	public void touch(Object key) {
		touched.add(key);
	}

	public List clearUntouched() {
		List results = new LinkedList();

		Iterator i = this.iterator();
		while (i.hasNext()) {
			Object j = i.next();
			if (!touched.contains(j)) {
				results.add(j);
				i.remove();
			}
		}

		return results;
	}
}
