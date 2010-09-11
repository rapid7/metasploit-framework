package com.metasploit.meterpreter;

import java.io.IOException;
import java.net.Socket;

/**
 * A channel for a {@link Socket}.
 * 
 * @author mihi
 */
public class SocketChannel extends Channel {

	private final Socket socket;

	/**
	 * Create a new socket channel.
	 * 
	 * @param meterpreter
	 *            The meterpreter this channel should be assigned to.
	 * @param socket
	 *            Socket of the channel
	 */
	public SocketChannel(Meterpreter meterpreter, Socket socket) throws IOException {
		super(meterpreter, socket.getInputStream(), socket.getOutputStream());
		this.socket = socket;
	}

	public void close() throws IOException {
		socket.close();
		super.close();
	}

	/**
	 * Get the socket.
	 */
	public Socket getSocket() {
		return socket;
	}
}
