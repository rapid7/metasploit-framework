package cortana.data;

import java.util.*;

/* A container for a host. */
public class Host {
	protected Map    sessions;
	protected Map    services;
	protected String address;
	protected Map    data;

	public Host(String address, Map data) {
		this.address = address;
		this.data    = data;
		sessions     = new HashMap();
		services     = new HashMap();

		fixOSValues();

		data.put("sessions", sessions);
		data.put("services", services);
	}

	public Map getData() {
		return data;
	}

	public Map getSessions() {
		return sessions;
	}

	public Map getServices() {
		return services;
	}

	public boolean hasService(String port) {
		return services.containsKey(port);
	}

	public Set serviceSet() {
		Set rv = new HashSet();
		Iterator i = services.keySet().iterator();
		while (i.hasNext()) {
			rv.add(new Service(address, i.next() + ""));
		}
		return rv;
	}

	/* fix up some operating system identifying information */
	protected void fixOSValues() {
		if ("".equals(data.get("os_name"))) {
			data.put("os_name", "Unknown");
		}
		else {
			data.put("os_match", data.get("os_name") + " " + data.get("os_flavor") + " " + data.get("os_sp"));
		}
		data.put("show", Boolean.TRUE);
	}

	public void update(Map data) {
		this.data.putAll(data);
		fixOSValues();
	}
}
