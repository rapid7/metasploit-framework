package msf;

import java.util.*;
import java.io.IOException;

/* Pool Metasploit console ids and make them available for reuse. Why? Two reasons. One,
   Metasploit 4.3-release has a nice race condition where every console.create call is
   a game of Russian roulette with an opportunity to bring the entire Metasploit daemon
   down. Two, each console.create call takes around 300ms. Armitage uses temporary consoles
   for a lot of things, this will help make these uses slightly snappier. */
public class ConsolePool implements RpcConnection {
	protected RpcConnection client;
	protected Set inactive = new HashSet();
	protected Set tracked  = new HashSet();

        public Object execute(String methodName) throws IOException {
		return execute(methodName, new Object[0]);
	}

        public Object execute(String methodName, Object[] params) throws IOException {
		if (methodName.equals("console.allocate")) {
			return allocate();
		}
		else if (methodName.equals("console.release")) {
			release((String)params[0]);
		}
		else if (methodName.equals("console.release_and_destroy")) {
			synchronized (this) {
				tracked.remove((String)params[0]);
			}
			release((String)params[0]);
		}
		return new HashMap();
	}

	public ConsolePool(RpcConnection client) {
		this.client = client;
	}

	public Map allocate() throws IOException {
		synchronized (this) {
			while (inactive.size() > 0) {
				Iterator i = inactive.iterator();
				Map rv = (Map)i.next();
				i.remove();

				/* clear any data from the console before we return it */
				Map temp = (Map)client.execute("console.read", new Object[] { rv.get("id") + "" });

				/* this is a sanity check to make sure this console is not dead or hung */
				if ("failure".equals(temp.get("result")) || "true".equals(temp.get("busy") + "") || "".equals(temp.get("prompt") + "")) {
					System.err.println("Kill Console: " + rv + " => " + temp);
					client.execute("console.destroy", new Object[] { rv.get("id") + "" });
				}
				else {
					//System.err.println("Reusing: " + rv + " => " + temp);
					return rv;
				}
			}
		}

		Map result = (Map)client.execute("console.create");

		/* keep track of consoles that are in the pool, so we know whether to
		   destroy or release them when asked to. We only release pooled consoles
		   because we know they're used a certain way (e.g., for temporary purposes,
		   not long running tasks that a user may have setup) */
		synchronized (this) {
			tracked.add(result.get("id") + "");
		}

		/* swallow the banner... making sure this is done will be part of the
		   contract of the console pool */
		client.execute("console.read", new Object[] { result.get("id") });
		//System.err.println("New console: " + result);
		return result;
	}

	public void release(String id) throws IOException {
		/* make sure we're in a "clean" console */
		HashMap rv = new HashMap();
		rv.put("id", id);

		boolean b;
		synchronized (this) {
			b = tracked.contains(id);
		}

		if (b) {
			//System.err.println("Added: " + rv + " to pool");
			client.execute("console.write", new Object[] { id, "back\n" });
			synchronized (this) {
				inactive.add(rv);
			}
		}
		else {
			//System.err.println("Destroyed: " + id);
			client.execute("console.destroy", new Object[] { id });
		}
	}
}
