package cortana.data;

import cortana.core.*;

import armitage.ArmitageTimerClient;
import armitage.ArmitageTimer;

import graph.Route;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

import msf.*;

public class Hosts extends ManagedData {
	protected RpcConnection  client;
	protected EventManager   manager;
	protected Map            hosts   = new HashMap();

	public Map getHostsData() {
		Map r = new HashMap();

		Iterator i = hosts.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry temp = (Map.Entry)i.next();
			r.put(temp.getKey(), ((Host)temp.getValue()).getData());
		}

		return r;
	}

	public Scalar getScalar() {
		if (cache == null)
			cache = FilterManager.convertAll(getHostsData());

		return cache;
	}

	public Map getHosts() {
		return hosts;
	}

	public Hosts(RpcConnection client, EventManager manager) {
		this.client  = client;
		this.manager = manager;
	}

	protected void fireHostEvent(String event, Iterator changes) {
		while (changes.hasNext()) {
			String addr = (String)changes.next();
			Stack argz = new Stack();
			argz.push(SleepUtils.getScalar(addr));
			manager.fireEventAsync(event, argz);
		}
	}

	public void processHosts(Map results) {
		if (!results.containsKey("hosts"))
			return;

		/* invalidate the cache */
		cache = null;

		Set currentHosts = new HashSet();
		currentHosts.addAll(hosts.keySet());

		Map  newHosts = new HashMap();

		List hostl = (List)results.get("hosts");
		Iterator i = hostl.iterator();

		while (i.hasNext()) {
			Map data = (Map)i.next();
			String address = data.get("address") + "";

			Host temp;
			if (hosts.containsKey(address)) {
				temp = (Host)hosts.get(address);
				temp.update(data);
			}
			else {
				temp = new Host(address, data);
			}

			newHosts.put(address, temp);
		}

		/* set the hosts info to the old host info */
		hosts = newHosts;

		/* fire eventz for host changes */
		if (!initial) {
			Set oldHosts = DataUtils.difference(currentHosts, newHosts.keySet());
			fireHostEvent("host_delete", oldHosts.iterator());

			Set newStuff = DataUtils.difference(newHosts.keySet(), currentHosts);
			fireHostEvent("host_add", newStuff.iterator());
		}

		/* fire an event for all hosts */
		Stack arg = new Stack();
		arg.push(FilterManager.convertAll(hostl));
		manager.fireEventAsync("hosts", arg);

		initial = false;
	}
}
