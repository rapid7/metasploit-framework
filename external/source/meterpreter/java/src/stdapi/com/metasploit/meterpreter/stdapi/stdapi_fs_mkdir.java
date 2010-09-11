package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_mkdir implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String path = request.getStringValue(TLVType.TLV_TYPE_DIRECTORY_PATH);
		File file = new File(Loader.cwd, path);
		if (!file.getParentFile().exists())
			file = new File(path);
		if (!file.getParentFile().exists() || !file.getParentFile().isDirectory()) {
			throw new IOException("Parent directory not found: " + path);
		}
		if (!file.mkdirs()) {
			throw new IOException("Cannot create directory " + file.getCanonicalPath());
		}
		return ERROR_SUCCESS;
	}
}
