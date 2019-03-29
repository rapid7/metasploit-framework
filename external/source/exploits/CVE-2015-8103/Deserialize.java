package ysoserial;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import ysoserial.payloads.util.Serializables;

/*
 * for testing payloads across process boundaries
 */
public class Deserialize {
	public static void main(final String[] args) throws ClassNotFoundException, IOException {
		final InputStream in = args.length == 0 ? System.in : new FileInputStream(new File(args[0]));
		Serializables.deserialize(in);
	}
}
