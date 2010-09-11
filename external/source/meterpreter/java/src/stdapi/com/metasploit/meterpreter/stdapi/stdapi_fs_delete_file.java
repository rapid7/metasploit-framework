package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_delete_file implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
		File file = new File(Loader.cwd, path);
		if (!file.exists())
			file = new File(path);
		if (!file.exists() || !file.isFile()) {
			throw new IOException("File not found: " + path);
		}
		if (!file.delete()) {
			throw new IOException("Cannot delete " + file.getCanonicalPath());
		}
		return ERROR_SUCCESS;
	}
}
