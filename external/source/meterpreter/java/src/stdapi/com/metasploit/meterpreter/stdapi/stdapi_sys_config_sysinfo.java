package com.metasploit.meterpreter.stdapi;

import java.net.InetAddress;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_config_sysinfo implements Command {
	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		response.add(TLVType.TLV_TYPE_COMPUTER_NAME, InetAddress.getLocalHost().getHostName());
		response.add(TLVType.TLV_TYPE_OS_NAME, System.getProperty("os.name") + " " + System.getProperty("os.version") + " (" + System.getProperty("os.arch") + ")");
		return ERROR_SUCCESS;
	}
}