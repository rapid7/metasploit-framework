package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
			Field fld;
			try {
				fld = URL.class.getDeclaredField("handlers");
			} catch (NoSuchFieldException ex) {
				try {
					// GNU Classpath (libgcj) calls this field differently
					fld = URL.class.getDeclaredField("ph_cache");					
				} catch (NoSuchFieldException ex2) {
					// throw the original exception
					throw ex;
				}
			}
			fld.setAccessible(true);
			Map handlers = (Map) fld.get(null);
			// Note that although this is a static initializer, it can happen 
			// that two threads are entering this spot at the same time: When
			// there is more than one classloader context (e. g. in a servlet
			// container with Spawn=0) and more than one of them is loading
			// a copy of this class at the same time. Work around this by
			// letting all of them use the same URL stream handler object.
			synchronized(handlers) {
				// do not use the "real" class name here as the same class
				// loaded in different classloader contexts is not the same
				// one for Java -> ClassCastException
				Object /*MemoryBufferURLStreamHandler*/ handler;
				
				if (handlers.containsKey("metasploitmembuff")) {
					handler = handlers.get("metasploitmembuff");
				} else {
					handler = new MemoryBufferURLStreamHandler();
					handlers.put("metasploitmembuff", handler);
				}
				
				// for the same reason, use reflection to obtain the files List
				files = (List) handler.getClass().getMethod("getFiles", new Class[0]).invoke(handler, new Object[0]);
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex.toString());
		}
	}

	/**
	 * Create a new URL from a byte array and its content type.
	 */
	public static URL createURL(byte[] data, String contentType) throws MalformedURLException {
		synchronized(files) {
			files.add(data);
			return new URL("metasploitmembuff", "", (files.size() - 1) + "/" + contentType);
		}
	}

	private final byte[] data;
	private final String contentType;

	protected MemoryBufferURLConnection(URL url) {
		super(url);
		String file = url.getFile();
		int pos = file.indexOf('/');
		synchronized (files) {
			data = (byte[]) files.get(Integer.parseInt(file.substring(0, pos)));
		}
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
