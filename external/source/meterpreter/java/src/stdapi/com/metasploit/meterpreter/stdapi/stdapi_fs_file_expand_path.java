package com.metasploit.meterpreter.stdapi;

import java.io.File;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;

public class stdapi_fs_file_expand_path implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
		if (path.equals("%COMSPEC%")) {
			response.add(TLVType.TLV_TYPE_FILE_PATH, getShellPath());
			return ERROR_SUCCESS;
		} else {
			return NotYetImplementedCommand.INSTANCE.execute(meterpreter, request, response);
		}
	}

	protected String getShellPath() {
		if (File.pathSeparatorChar == ';')
			return "cmd.exe";
		else
			return "/bin/sh";
	}
}
