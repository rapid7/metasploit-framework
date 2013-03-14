package cortana.core;

import java.util.*;
import sleep.runtime.*;
import sleep.bridges.*;
import sleep.engine.*;
import sleep.interfaces.*;

public class FilterManager {
	protected Map filters;

	protected List getFilters(String name) {
		if (filters.containsKey(name)) {
			return (List)filters.get(name);
		}
		else {
			filters.put(name, new LinkedList());
			return (List)filters.get(name);
		}
	}

	public Loadable getBridge() {
		return new Filters(this);
	}

	public FilterManager() {
		filters = new HashMap();
	}

	private static class Filter {
		protected SleepClosure filter;

		public Filter(SleepClosure filter) {
			this.filter  = filter;
		}

		public SleepClosure getClosure() {
			return filter;
		}
	}

	public void addFilter(String filter, SleepClosure c) {
		getFilters(filter).add(new Filter(c));
	}

	/* convert the Java object to a Sleep data type (recursively) */
	public static Scalar convertAll(Object data) {
		if (data instanceof Collection) {
			Scalar temp = SleepUtils.getArrayScalar();
			Iterator i = ((Collection)data).iterator();
			while (i.hasNext()) {
				temp.getArray().push(convertAll(i.next()));
			}
			return temp;
		}
		else if (data instanceof Map) {
			Scalar temp = SleepUtils.getHashScalar();
			Iterator i = ((Map)data).entrySet().iterator();
			while (i.hasNext()) {
				Map.Entry entry = (Map.Entry)i.next();
				Scalar key   = SleepUtils.getScalar(entry.getKey() + "");
				Scalar value = temp.getHash().getAt(key);
				value.setValue(convertAll(entry.getValue()));
			}
			return temp;
		}
		else {
			return ObjectUtilities.BuildScalar(true, data);
		}
	}

	public Stack filterScalarData(String eventName, Stack args) {
		List filters = getFilters(eventName);

		if (filters.size() == 0)
			return args;

		Iterator i = filters.iterator();

		ScriptInstance script = null;

		while (i.hasNext()) {
			Filter f = (Filter)i.next();

			if (!f.getClosure().getOwner().isLoaded()) {
				i.remove();
				continue;
			}

			Scalar temp = SleepUtils.runCode(f.getClosure(), eventName, null, args);
			script = f.getClosure().getOwner();
			args.clear();

			if (temp.getArray() != null) {
				ScalarArray ar = temp.getArray();
				while (ar.size() > 0) {
					Scalar tempz = ar.pop();
					args.push(tempz);
				}
			}
			else {
				throw new RuntimeException("filter " + f.getClosure() + " did not return an array");
			}
		}

		return args;
	}

	public Object[] filterData(String eventName, Object[] data) {
		if (getFilters(eventName).size() == 0)
			return data;

		Stack args = new Stack();
		int offset = data.length - 1;
		for (int x = 0; x < data.length; x++) {
			args.push(convertAll(data[offset - x]));
		}

		Stack res = filterScalarData(eventName, args);

		Object rv[] = new Object[res.size()];
		//System.err.println("Filter: " + eventName);
		for (int x = 0; x < rv.length; x++) {
			rv[x] = ObjectUtilities.buildArgument(Object.class, (Scalar)res.pop(), null);
			//System.err.println("    '" + rv[x] + "', " + rv[x].getClass());
		}
		return rv;
	}
}
