package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

/**
 * An {@link URLConnection} for an URL that is stored completely in memory.
 * 
 * @author mihi
 */
public class MemoryBufferURLConnection extends URLConnection {

	private static List files = new ArrayList();

	static {
		// tweak the cache of already loaded protocol handlers via reflection
		try {
			Field fld = URL.class.getDeclaredField("handlers");
			fld.setAccessible(true);
			Hashtable handlers = (Hashtable) fld.get(null);
			handlers.put("metasploitmembuff", new MemoryBufferURLStreamHandler());
		} catch (Exception ex) {
			throw new RuntimeException(ex.toString());
		}
	}

	/**
	 * Create a new URL from a byte array and its content type.
	 */
	public static URL createURL(byte[] data, String contentType) throws MalformedURLException {
		files.add(data);
		return new URL("metasploitmembuff", "", (files.size() - 1) + "/" + contentType);
	}

	private final byte[] data;
	private final String contentType;

	protected MemoryBufferURLConnection(URL url) {
		super(url);
		String file = url.getFile();
		int pos = file.indexOf('/');
		data = (byte[]) files.get(Integer.parseInt(file.substring(0, pos)));
		contentType = file.substring(pos + 1);
	}

	public void connect() throws IOException {
	}

	public InputStream getInputStream() throws IOException {
		return new ByteArrayInputStream(data);
	}

	public int getContentLength() {
		return data.length;
	}

	public String getContentType() {
		return contentType;
	}
}
