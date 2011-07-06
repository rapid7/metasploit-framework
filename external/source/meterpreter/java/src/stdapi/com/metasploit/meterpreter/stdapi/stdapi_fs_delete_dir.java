package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_delete_dir implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String path = request.getStringValue(TLVType.TLV_TYPE_DIRECTORY_PATH);
		File file = Loader.expand(path);
		if (!file.exists() || !file.isDirectory()) {
			throw new IOException("Directory not found: " + path);
		}
		if (!file.delete()) {
			throw new IOException("Cannot delete directory " + file.getCanonicalPath());
		}
		return ERROR_SUCCESS;
	}
}
