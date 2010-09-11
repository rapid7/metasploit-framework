package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_channel_close implements Command {
	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		Channel c = meterpreter.getChannel(request.getIntValue(TLVType.TLV_TYPE_CHANNEL_ID), false);
		if (c != null)
			c.close();
		return ERROR_SUCCESS;
	}
}
