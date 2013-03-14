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

public class Loots extends ManagedData {
	protected RpcConnection  client;
	protected EventManager   manager;
	protected Map		 loots  = new HashMap();

	public Collection getLoots() {
		return loots.values();
	}

	public Scalar getScalar() {
		if (cache == null)
			cache = FilterManager.convertAll(getLoots());

		return cache;
	}

	public Loots(RpcConnection client, EventManager manager) {
		this.client  = client;
		this.manager = manager;
	}

	/* a shortcut to fire route events */
	protected void fireLootEvents(String name, Iterator changes) {
		if (initial)
			return;

		while (changes.hasNext()) {
			String temp = (String)changes.next();
			Stack arg = new Stack();
			arg.push( FilterManager.convertAll(loots.get(temp)) );
			manager.fireEventAsync(name, arg);
		}
	}

	public void processLoots(Map results) {
		if (!results.containsKey("loots"))
			return;

		/* invalidate the cache */
		cache = null;

		/* create a set of existing loots */
		Set oldLoots = new HashSet();
		oldLoots.addAll(loots.keySet());
		loots.clear();

		/* parse and add loots */

		Iterator i = ((Collection)results.get("loots")).iterator();
		while (i.hasNext()) {
			Map temp = (Map)i.next();
			loots.put(temp.get("path") + "", temp);
		}

		/* setup a set of our new loots */
		Set currentLoots = new HashSet();
		currentLoots.addAll(loots.keySet());

		/* now... bucket our loots and fire some events */
		Set newLoots = DataUtils.difference(currentLoots, oldLoots);
		fireLootEvents("loot_add", newLoots.iterator());

		//Set goneLoots = DataUtils.difference(oldLoots, currentLoots);
		/* there's no such thing as a loot_delete event since loot goes away when a host is deleted */

		/* ok, we've refreshed the loots too, let the world know eh? */
		Stack arg = new Stack();
		arg.push(FilterManager.convertAll(loots.values()));
		manager.fireEventAsync("loots", arg);

		initial = false;
	}
}
