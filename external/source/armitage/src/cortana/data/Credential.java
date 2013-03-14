package cortana.data;

import java.util.*;
import sleep.runtime.*;

/* represent a credential in a Set */
public class Credential {
	protected String host;
	protected String port;
	protected String user;
	protected String pass;
	protected String type;

	public String getHost() {
		return host;
	}

	public String getPort() {
		return port;
	}

	public Credential(String host, String port, String user, String pass, String type) {
		this.host = host;
		this.port = port;
		this.user = user;
		this.pass = pass;
		this.type = type;
	}

	public Stack arguments() {
		Stack arguments = new Stack();
		arguments.push(SleepUtils.getScalar(type));
		arguments.push(SleepUtils.getScalar(pass));
		arguments.push(SleepUtils.getScalar(user));
		arguments.push(SleepUtils.getScalar(port));
		arguments.push(SleepUtils.getScalar(host));
		return arguments;
	}

	public boolean equals(Object o) {
		if (o instanceof Credential) {
			Credential t = (Credential)o;
			return (t.host.equals(host) && t.port.equals(port) && t.user.equals(user) && t.pass.equals(pass) && t.type.equals(type));
		}
		return false;
	}

	public int hashCode() {
		return host.hashCode() + port.hashCode() + user.hashCode() + pass.hashCode() + type.hashCode();
	}

	public String toString() {
		return user + ":" + pass + "@" + host + ":" + port + "/" + type;
	}
}
