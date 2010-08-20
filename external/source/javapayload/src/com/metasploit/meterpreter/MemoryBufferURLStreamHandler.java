package com.metasploit.meterpreter;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
 * An {@link URLStreamHandler} for a {@link MemoryBufferURLConnection}
 * 
 * @author mihi
 */
public class MemoryBufferURLStreamHandler extends URLStreamHandler {
	protected URLConnection openConnection(URL u) throws IOException {
		return new MemoryBufferURLConnection(u);
	}
}
