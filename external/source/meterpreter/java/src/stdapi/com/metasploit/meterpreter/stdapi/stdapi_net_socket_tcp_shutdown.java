package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.net.Socket;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.SocketChannel;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_net_socket_tcp_shutdown implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

		SocketChannel c = (SocketChannel) meterpreter.getChannel(request.getIntValue(TLVType.TLV_TYPE_CHANNEL_ID), true);

		Socket socket = c.getSocket();
		int how = request.getIntValue(TLVType.TLV_TYPE_SHUTDOWN_HOW);
		shutdown(socket, how);

		return ERROR_SUCCESS;
	}

	protected void shutdown(Socket socket, int how) throws IOException {
		socket.close();
	}
}
