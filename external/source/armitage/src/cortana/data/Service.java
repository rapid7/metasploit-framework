package cortana.data;

import java.util.*;
import sleep.runtime.*;

/* represent a host/port pair in a Set */
public class Service {
	protected String host;
	protected String port;

	public String getHost() {
		return host;
	}

	public String getPort() {
		return port;
	}

	public Service(String host, String port) {
		this.host = host;
		this.port = port;
	}

	public Stack arguments() {
		Stack arguments = new Stack();
		arguments.push(SleepUtils.getScalar(port));
		arguments.push(SleepUtils.getScalar(host));
		return arguments;
	}

	public boolean equals(Object o) {
		if (o instanceof Service) {
			Service t = (Service)o;
			return (t.host.equals(host) && t.port.equals(port));
		}
		return false;
	}

	public int hashCode() {
		return host.hashCode() + port.hashCode();
	}

	public String toString() {
		return host + ":" + port;
	}
}
