package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_channel_eof implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		int id = request.getIntValue(TLVType.TLV_TYPE_CHANNEL_ID);
		if (id == 0) {
			response.add(TLVType.TLV_TYPE_BOOL, false);
		} else {
			Channel c = meterpreter.getChannel(id, true);
			response.add(TLVType.TLV_TYPE_BOOL, c.isEOF());
		}
		return ERROR_SUCCESS;
	}
}
