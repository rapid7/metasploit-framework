package rmi;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.UnmarshalException;

public class RMICaptureServer {
	
	// http://download.oracle.com/javase/1.3/docs/guide/rmi/spec/rmi-protocol.html

	public static void main(String[] args) throws Exception {
		FileOutputStream fos = new FileOutputStream("build/rmipacket");
		ServerSocket ss = new ServerSocket(11099);
		Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					RMISender.main(new String[] {"file:./rmidummy.jar", "localhost", "11099"});
				} catch (UnmarshalException ex) {
					// expected
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		});
		t.setDaemon(true);
		t.start();
		Socket s = ss.accept();
		ss.close();
		DataInputStream in = new DataInputStream(s.getInputStream());
		DataOutputStream out = new DataOutputStream(s.getOutputStream());
		
		byte[] hdr = new byte[7];
		in.readFully(hdr);
		if (!new String(hdr, "ISO-8859-1").equals("JRMI\0\2K"))
			throw new IOException("Unsupported RMI header");
		
		out.write('N');
		out.writeUTF("127.0.0.1");
		out.writeInt(11099);
		out.flush();
		
		in.readUTF();
		in.readInt();
		
		s.setSoTimeout(1000);
		try {
		byte[] buf = new byte[4096];
		int len;
		while ((len = in.read(buf)) != -1) {
			fos.write(buf, 0, len);
		}
		} catch (InterruptedIOException ex) {
			// we are done
		}
		fos.close();
	}
}
