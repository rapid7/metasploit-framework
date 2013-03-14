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

public class Credentials extends ManagedData {
	protected RpcConnection  client;
	protected EventManager   manager;
	protected List           creds = new LinkedList();

	public Credentials(RpcConnection client, EventManager manager) {
		this.client  = client;
		this.manager = manager;
	}

	public List getCredentials() {
		return creds;
	}

	public Scalar getScalar() {
		if (cache == null)
			cache = FilterManager.convertAll(getCredentials());

		return cache;
	}

	protected void fireCredentialEvent(String event, Iterator crds) {
		if (isInitial())
			return;

		while (crds.hasNext()) {
			Credential t = (Credential)crds.next();
			manager.fireEventAsync(event, t.arguments());
		}
	}

	protected Set toSet(List results) {
		Set temp = new HashSet();
		Iterator i = results.iterator();
		while (i.hasNext()) {
			Map data = (Map)i.next();
			String host = data.get("host") + "";
			String port = data.get("port") + "";
			String user = data.get("user") + "";
			String pass = data.get("pass") + "";
			String type = data.get("ptype") + "";

			temp.add(new Credential(host, port, user, pass, type));
		}
		return temp;
	}

	public void processCreds(Map results) {
		if (!results.containsKey("creds"))
			return;

		/* invalidate our cache */
		cache = null;

		/* old creds */
		Set oldCredentials = toSet(creds);

		/* creeedz baby */
		creds = (List)results.get("creds");
		Set newCredentials = toSet(creds);

		/* fire a message for the creds that we now see */
		if (!initial) {
			Set newStuff = DataUtils.difference(newCredentials, oldCredentials);
			fireCredentialEvent("credential_add", newStuff.iterator());

			Set deletedStuff = DataUtils.difference(oldCredentials, newCredentials);
			fireCredentialEvent("credential_delete", deletedStuff.iterator());
		}

		/* fire a generic updated message */
		Stack args = new Stack();
		args.push(FilterManager.convertAll(creds));
		manager.fireEventAsync("credentials", args);

		initial = false;
	}
}
