package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.net.Socket;

public class stdapi_net_socket_tcp_shutdown_V1_3 extends stdapi_net_socket_tcp_shutdown {

	protected void shutdown(Socket socket, int how) throws IOException {
		switch (how) {

		case 0: // shutdown reading
			socket.shutdownInput();
			break;

		case 1: // shutdown writing
			socket.shutdownOutput();
			break;

		case 2: // shutdown reading and writing
			socket.shutdownInput();
			socket.shutdownOutput();
			break;

		default:
			throw new IllegalArgumentException("Invalid value for TLV_TYPE_SHUTDOWN_HOW: " + how);
		}
	}
}
