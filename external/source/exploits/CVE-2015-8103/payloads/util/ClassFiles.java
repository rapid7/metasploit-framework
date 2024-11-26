package ysoserial.payloads.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class ClassFiles {
	public static String classAsFile(final Class<?> clazz) {
		return classAsFile(clazz, true);
	}
	
	public static String classAsFile(final Class<?> clazz, boolean suffix) {
		String str;
		if (clazz.getEnclosingClass() == null) {
			str = clazz.getName().replace(".", "/");
		} else {
			str = classAsFile(clazz.getEnclosingClass(), false) + "$" + clazz.getSimpleName();
		}
		if (suffix) {
			str += ".class";			
		}
		return str;  
	}

	public static byte[] classAsBytes(final Class<?> clazz) {
		try {
			final byte[] buffer = new byte[1024];
			final String file = classAsFile(clazz);
			final InputStream in = ClassFiles.class.getClassLoader().getResourceAsStream(file);
			if (in == null) {
				throw new IOException("couldn't find '" + file + "'");
			}
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			int len;
			while ((len = in.read(buffer)) != -1) {
				out.write(buffer, 0, len);
			}
			return out.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
}
