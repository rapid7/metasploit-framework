// Based on the example from http://www.java2s.com/Code/Java/JDK-6/CompilingfromMemory.htm

package javaCompile;

import java.io.PrintStream;
import java.io.FilterOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import sun.security.tools.KeyTool;
import sun.security.tools.JarSigner;

public class SignJar {
	
	static PrintStream filteredstream =  
		new PrintStream(
			new FilteredStream(
				new ByteArrayOutputStream()));

	public static void KeyToolMSF( String[] args ) {
		try {
			RedirectStd();
			KeyTool.main( args );
		} catch( Exception ex ) { ex.printStackTrace(); }
	} 

	public static void JarSignerMSF( String[] args ) {
		try {
			RedirectStd();
			JarSigner.main( args );
		} catch( Exception ex ) { ex.printStackTrace(); }
	}

	private static void RedirectStd() {
		try {
			System.setOut( filteredstream );
			System.setErr( filteredstream );
		} catch( Exception ex ) { ex.printStackTrace(); }
	}

	static class FilteredStream extends FilterOutputStream {
		public FilteredStream( OutputStream aStream ) { super ( aStream ); }
		
		public void write( byte b[] ) throws IOException {
			String aString = new String( b );
			// Do stuff with the output.
		}

		public void write( byte b[], int off, int len) throws IOException {
			String aString = new String( b, off, len );
			// Do stuff with the output.
		}
	}
}
