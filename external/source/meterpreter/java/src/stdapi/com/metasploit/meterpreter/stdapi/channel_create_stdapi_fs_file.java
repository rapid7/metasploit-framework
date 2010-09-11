package com.metasploit.meterpreter.stdapi;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;

public class channel_create_stdapi_fs_file implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String fpath = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
		String mode = request.getStringValue(TLVType.TLV_TYPE_FILE_MODE, "rb");
		Channel channel;
		if (mode.equals("r") || mode.equals("rb") || mode.equals("rbb")) {
			channel = null;
			if (fpath.equals("...")) {
				byte[] data = meterpreter.getErrorBuffer();
				if (data != null)
					channel = new Channel(meterpreter, new ByteArrayInputStream(data), null);
			}
			if (channel == null)
				channel = new Channel(meterpreter, new FileInputStream(new File(Loader.cwd, fpath)), null);
		} else if (mode.equals("r") || mode.equals("wb") || mode.equals("wbb")) {
			channel = new Channel(meterpreter, new ByteArrayInputStream(new byte[0]), new FileOutputStream(new File(Loader.cwd, fpath).getPath(), false));
		} else if (mode.equals("a") || mode.equals("ab") || mode.equals("abb")) {
			channel = new Channel(meterpreter, new ByteArrayInputStream(new byte[0]), new FileOutputStream(new File(Loader.cwd, fpath).getPath(), true));
		} else {
			NotYetImplementedCommand.INSTANCE.execute(meterpreter, request, response);
			throw new IllegalArgumentException("Unsupported file mode: " + mode);
		}
		response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
		return ERROR_SUCCESS;
	}
}
