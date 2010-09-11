package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_channel_open implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String channelType = request.getStringValue(TLVType.TLV_TYPE_CHANNEL_TYPE);
		Command channelCreator = meterpreter.getCommandManager().getCommand("channel_create_" + channelType);
		return channelCreator.execute(meterpreter, request, response);
	}
}
