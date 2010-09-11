package com.metasploit.meterpreter.stdapi;

import java.net.InetAddress;
import java.net.ServerSocket;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.ServerSocketChannel;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class channel_create_stdapi_net_tcp_server implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String localHost = request.getStringValue(TLVType.TLV_TYPE_LOCAL_HOST);
		int localPort = request.getIntValue(TLVType.TLV_TYPE_LOCAL_PORT);
		ServerSocket ss;
		if (localHost.equals("0.0.0.0"))
			ss = new ServerSocket(localPort);
		else
			ss = new ServerSocket(localPort, 50, InetAddress.getByName(localHost));
		Channel channel = new ServerSocketChannel(meterpreter, ss);
		response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
		return ERROR_SUCCESS;
	}
}
