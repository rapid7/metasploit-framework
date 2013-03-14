package com.metasploit.meterpreter.stdapi;

import java.io.FileInputStream;
import java.security.MessageDigest;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public abstract class HashCommand implements Command {

	protected abstract String getAlgorithm();

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		FileInputStream in = new FileInputStream(Loader.expand(request.getStringValue(TLVType.TLV_TYPE_FILE_PATH)));
		MessageDigest md = MessageDigest.getInstance(getAlgorithm());
		byte[] buf = new byte[4096];
		int len;
		while ((len = in.read(buf)) != -1) {
			md.update(buf, 0, len);
		}
		response.add(TLVType.TLV_TYPE_FILE_NAME, new String(md.digest(), "ISO-8859-1"));
		return ERROR_SUCCESS;
	}
}
