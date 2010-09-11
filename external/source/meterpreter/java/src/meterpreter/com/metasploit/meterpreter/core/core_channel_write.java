package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_channel_write implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		Channel c = meterpreter.getChannel(request.getIntValue(TLVType.TLV_TYPE_CHANNEL_ID), true);
		byte[] data = request.getRawValue(TLVType.TLV_TYPE_CHANNEL_DATA);
		int len = request.getIntValue(TLVType.TLV_TYPE_LENGTH);
		c.write(data, len, request);
		response.add(TLVType.TLV_TYPE_LENGTH, len);
		return ERROR_SUCCESS;
	}
}
