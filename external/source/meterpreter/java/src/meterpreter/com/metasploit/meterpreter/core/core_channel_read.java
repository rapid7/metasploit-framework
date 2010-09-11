package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_channel_read implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		Channel channel = meterpreter.getChannel(request.getIntValue(TLVType.TLV_TYPE_CHANNEL_ID), true);
		int len = request.getIntValue(TLVType.TLV_TYPE_LENGTH);
		byte[] data = channel.read(len);
		if (data == null)
			return ERROR_FAILURE;
		response.add(TLVType.TLV_TYPE_CHANNEL_DATA, data);
		return ERROR_SUCCESS;
	}
}
