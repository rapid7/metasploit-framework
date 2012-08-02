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

public class Services extends ManagedData {
	protected RpcConnection  client;
	protected EventManager   manager;
	protected Hosts          hosts;
	protected List           services = new LinkedList();

	public Services(Hosts hosts, RpcConnection client, EventManager manager) {
		this.client  = client;
		this.manager = manager;
		this.hosts   = hosts;
	}

	public List getServices() {
		return services;
	}

	public Scalar getScalar() {
		if (cache == null)
			cache = FilterManager.convertAll(getServices());

		return cache;
	}

	protected void fireServiceEvent(String event, Iterator services) {
		while (services.hasNext()) {
			Service t = (Service)services.next();
			if (event.equals("service_add")) {
				manager.fireEventAsync("service_add_" + t.getPort(), t.arguments());
				manager.fireEventAsync("service_add", t.arguments());
			}
			else {
				manager.fireEventAsync(event, t.arguments());
			}
		}
	}

	public void processServices(Map results) {
		if (hosts.isInitial())
			return;

		if (!results.containsKey("services"))
			return;

		/* invalidate the cache */
		cache = null;
		hosts.cache = null;

		Set oldServices = new HashSet();
		Set newServices = new HashSet();

		/* clear all of the services */
		Iterator j = hosts.getHosts().values().iterator();
		while (j.hasNext()) {
			Host host = (Host)j.next();
			oldServices.addAll(host.serviceSet());
			host.getServices().clear();
		}

		/* install all the services into our hosts data */
		services = (List)results.get("services");
		Iterator i = services.iterator();
		while (i.hasNext()) {
			Map data = (Map)i.next();
			String host = data.get("host") + "";
			String port = data.get("port") + "";

			Host temp = (Host)hosts.getHosts().get(host);
			if (temp != null) {
				Map srvc = temp.getServices();
				srvc.put(port, data);
				newServices.add(new Service(host, port));
			}
		}

		/* fire a message for various services that we now see */
		if (!initial) {
			Set newStuff = DataUtils.difference(newServices, oldServices);
			fireServiceEvent("service_add", newStuff.iterator());

			Set deletedStuff = DataUtils.difference(oldServices, newServices);
			fireServiceEvent("service_delete", deletedStuff.iterator());
		}

		/* fire a generic services updated message */
		Stack args = new Stack();
		args.push(FilterManager.convertAll(services));
		manager.fireEventAsync("services", args);

		initial = false;
	}
}
