package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

/**
 * A channel for a {@link DatagramSocket}.
 * 
 * @author mihi
 */
public class DatagramSocketChannel extends Channel {

	private final DatagramSocket datagramSocket;
	private boolean closed = false;

	/**
	 * Create a new socket channel.
	 * 
	 * @param meterpreter
	 *            The meterpreter this channel should be assigned to.
	 * @param socket
	 *            Socket of the channel
	 */
	public DatagramSocketChannel(Meterpreter meterpreter, DatagramSocket datagramSocket) throws IOException {
		super(meterpreter, new ByteArrayInputStream(new byte[0]), null);
		this.datagramSocket = datagramSocket;
		new AcceptThread().start();
	}

	public void write(byte[] data, int length, TLVPacket request) throws IOException {
		String remoteHostName = (String) request.getValue(TLVType.TLV_TYPE_PEER_HOST, null);
		InetAddress remoteHost = null;
		int remotePort = 0;
		if (remoteHostName != null) {
			remoteHost = InetAddress.getByName(remoteHostName);
			remotePort = request.getIntValue(TLVType.TLV_TYPE_PEER_PORT);
		}
		write(data, length, remoteHost, remotePort);
	}

	private void write(byte[] data, int length, InetAddress remoteHost, int remotePort) throws IOException {
		if (remoteHost == null) {
			remoteHost = datagramSocket.getInetAddress();
			remotePort = datagramSocket.getPort();
		}
		DatagramPacket dp = new DatagramPacket(data, length, remoteHost, remotePort);
		datagramSocket.send(dp);
	}

	public void close() throws IOException {
		closed = true;
		datagramSocket.close();
		super.close();
	}
	
	Meterpreter getMeterpreter() {
		return meterpreter;
	}

	private class AcceptThread extends Thread {
		public void run() {
			try {
				byte[] datagram = new byte[65536];
				while (true) {
					try {
					DatagramPacket dp = new DatagramPacket(datagram, datagram.length);
					datagramSocket.receive(dp);
					byte[] data = new byte[dp.getLength()];
					System.arraycopy(datagram, 0, data, 0, dp.getLength());
					TLVPacket tlv = new TLVPacket();
					tlv.add(TLVType.TLV_TYPE_CHANNEL_ID, getID());
					tlv.add(TLVType.TLV_TYPE_PEER_HOST, dp.getAddress().getHostAddress());
					tlv.add(TLVType.TLV_TYPE_PEER_PORT, dp.getPort());
					tlv.add(TLVType.TLV_TYPE_CHANNEL_DATA, data);
					tlv.add(TLVType.TLV_TYPE_LENGTH, data.length);
					getMeterpreter().writeRequestPacket("core_channel_write", tlv);
					} catch (SocketException t) {
						// dirty hack since later java versions add more of those...
						if (!t.getClass().getName().endsWith("UnreachableException"))
							throw t;
					}
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
