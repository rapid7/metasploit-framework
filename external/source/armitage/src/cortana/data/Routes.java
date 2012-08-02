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

public class Routes extends ManagedData {
	protected RpcConnection  client;
	protected EventManager   manager;
	protected List		 routes  = new LinkedList();

	public List getRoutes() {
		return routes;
	}

	public Scalar getScalar() {
		if (cache == null)
			cache = FilterManager.convertAll(getRoutes());

		return cache;
	}

	public Routes(RpcConnection client, EventManager manager) {
		this.client  = client;
		this.manager = manager;
	}

	/* a shortcut to fire route events */
	protected void fireRouteEvents(String name, Iterator routes) {
		if (initial)
			return;

		while (routes.hasNext()) {
			Route temp = (Route)routes.next();
			Stack arg = new Stack();
			arg.push(FilterManager.convertAll(temp));
			manager.fireEventAsync(name, arg);
		}
	}

	public void processRoutes(Map results) {
		/* invalidate the cache */
		cache = null;

		/* create a set of existing routes */
		Set oldRoutes = new HashSet();
		oldRoutes.addAll(routes);

		routes.clear();

		/* parse and add routes */

		Iterator i = results.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry temp = (Map.Entry)i.next();
			String sid = temp.getKey() + "";
			Map session = (Map)temp.getValue();

			if (!"".equals(session.get("routes") + "")) {
				String[] routez = (session.get("routes") + "").split(",");
				for (int x = 0; x < routez.length; x++) {
					String zz[] = routez[x].split("/");
					routes.add(new Route(zz[0], zz[1], sid));
				}
			}
		}

		/* setup a set of our new routes */
		Set currentRoutes = new HashSet();
		currentRoutes.addAll(routes);

		/* now... bucket our routes and fire some events */
		Set newRoutes = DataUtils.difference(currentRoutes, oldRoutes);
		fireRouteEvents("route_add", newRoutes.iterator());

		Set goneRoutes = DataUtils.difference(oldRoutes, currentRoutes);
		fireRouteEvents("route_delete", goneRoutes.iterator());

		/* ok, we've refreshed the routes too, let the world know eh? */
		Stack arg = new Stack();
		arg.push(FilterManager.convertAll(routes));
		manager.fireEventAsync("routes", arg);

		initial = false;
	}
}
