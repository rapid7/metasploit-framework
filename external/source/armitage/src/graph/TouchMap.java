package graph;

import java.util.*;

/** A touch map lets me start an operation, "touch" each updated node, and then delete any untouched node */
public class TouchMap extends HashMap {
	protected Set touched = new HashSet();

	public void startUpdates() {
		touched.clear();
	}

	public void touch(Object key) {
		touched.add(key);
	}

	public List clearUntouched() {
		List results = new LinkedList();

		Iterator i = this.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry j = (Map.Entry)i.next();
			if (!touched.contains(j.getKey())) {
				results.add(j);
				i.remove();
			}
		}

		return results;
	}
}
