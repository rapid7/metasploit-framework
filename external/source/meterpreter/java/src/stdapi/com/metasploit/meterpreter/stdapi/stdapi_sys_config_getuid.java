package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_config_getuid implements Command {
	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		response.add(TLVType.TLV_TYPE_USER_NAME, System.getProperty("user.name"));
		return ERROR_SUCCESS;
	}
}