package com.metasploit.meterpreter.stdapi;

import java.io.File;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_separator implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		response.add(TLVType.TLV_TYPE_STRING, File.separator);
		return ERROR_SUCCESS;
	}

}
