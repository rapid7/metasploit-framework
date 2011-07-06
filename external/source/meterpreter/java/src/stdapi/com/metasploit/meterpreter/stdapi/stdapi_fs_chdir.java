package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_chdir implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String path = request.getStringValue(TLVType.TLV_TYPE_DIRECTORY_PATH);
		File f = Loader.expand(path);
		if (!f.exists() || !f.isDirectory()) {
				throw new IOException("Path not found: " + path);
		}
		Loader.cwd = f.getCanonicalFile();
		return ERROR_SUCCESS;
	}
}
