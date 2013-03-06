package msf;

import java.io.*;
import java.net.*;
import java.text.*;
import java.util.*;
import javax.xml.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;

/* A self-expiring cache for RPC calls */
public class RpcCacheImpl implements Runnable {
	protected RpcConnection connection = null;
	protected Map cache = new HashMap();
	protected Map filters = new HashMap();

	private static class CacheEntry {
		public long last = 0L;
		public long wait = 2000L;
		public Object response = null;

		public boolean isExpired() {
			return (System.currentTimeMillis() - last) > wait;
		}

		public void touch(String method, long executeTime) {
			/* throttle the next call if this takes too long to execute */
			if (executeTime > 500) {
				wait = 5000L;
				System.err.println("* " + method + " took " + executeTime + "ms - throttling next call");
			}
			else {
				wait = 2000L;
			}

			last = System.currentTimeMillis();
		}
	}

	public RpcCacheImpl(RpcConnection connection) {
		this.connection = connection;
		new Thread(this).start();
	}

	public void setFilter(String user, Object[] filter) {
		synchronized (this) {
			if (filter == null || filter.length == 0) {
				filters.remove(user);
				return;
			}

			Map temp = (Map)filter[0];
			if (temp.size() == 0) {
				filters.remove(user);
			}
			else {
				filters.put(user, filter);
			}
		}
	}

	public Object execute(String user, String methodName) throws IOException {
		return execute(methodName, null);
	}

	public Object execute_cache(String cacheKey, String methodName, Object[] params) throws IOException {
		synchronized (this) {
			CacheEntry entry = null;

			if (cache.containsKey(cacheKey)) {
				entry = (CacheEntry)cache.get(cacheKey);
				if (!entry.isExpired()) {
					return entry.response;
				}
			}
			else {
				entry = new CacheEntry();
				cache.put(cacheKey, entry);
			}

			long time = System.currentTimeMillis();
			if (params == null) {
				entry.response = connection.execute(methodName);
			}
			else {
				entry.response = connection.execute(methodName, params);
			}
			time = System.currentTimeMillis() - time;
			entry.touch(methodName, time);

			return entry.response;
		}
	}

	private static String cacheKey(String method, Object[] args) {
		Map temp = (Map)args[0];
		StringBuffer key = new StringBuffer();
		key.append(method + ":");
		key.append(temp.get("hosts"));
		key.append(";");
		key.append(temp.get("os"));
		key.append(";");
		key.append(temp.get("ports"));
		key.append(";");
		key.append(temp.get("session"));
		key.append(";");
		key.append(temp.get("labels"));
		return key.toString();
	}

	private static final Object[] emptyFilter = new Object[] { new HashMap() };

	public Object execute(String user, String methodName, Object[] params) throws IOException {
		synchronized (this) {
			/* user has a dynamic workspace... let's work with that. */
			if (!methodName.equals("session.list") && filters.containsKey(user)) {
				/* setup the filter */
				Object[] filter = (Object[])filters.get(user);
				connection.execute("db.filter", filter);

				/* calculate the cache key for the filter */
				String key = cacheKey(methodName, filter);

				/* execute the function (caching the results too) */
				Object response = execute_cache(key, methodName, params);

				/* reset the filter */
				connection.execute("db.filter", emptyFilter);

				return response;
			}
			else if (methodName.equals("session.list")) {
				/* do something special */
				synchronized (this) {
					if (sessions != null)
						return sessions;
					else
						return execute_cache(methodName, methodName, params);
				}
			}
			else {
				return execute_cache(methodName, methodName, params);
			}
		}
	}

	protected Object sessions = null;

	public void run() {
		while (true) {
			try {
				Object temp = connection.execute("session.list");
				synchronized (this) {
					sessions = temp;
				}
			}
			catch (IOException ex) {
				ex.printStackTrace();
				return;
			}

			try {
				Thread.sleep(2000);
			}
			catch (InterruptedException iex) {
				iex.printStackTrace();
			}
		}
	}
}
