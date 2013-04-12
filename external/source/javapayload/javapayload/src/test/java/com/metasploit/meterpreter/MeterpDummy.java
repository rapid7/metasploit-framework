package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;


/**
 * Dummy/Stub meterpreter class for unit tests.
 */
public class MeterpDummy {

	public MeterpDummy(DataInputStream in, OutputStream rawOut, boolean loadExtensions, boolean redirectErrors) throws Exception {
		byte[] buffer = new byte[in.readInt()];
		in.readFully(buffer);
		DataOutputStream out = new DataOutputStream(rawOut);
		out.write(buffer);
		out.writeBoolean(loadExtensions);
		out.writeBoolean(redirectErrors);
		out.close();
	}
}
