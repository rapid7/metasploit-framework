package com.metasploit.meterpreter.stdapi;

import java.io.IOException;

public class stdapi_sys_process_execute_V1_3 extends stdapi_sys_process_execute {
	protected Process execute(String[] cmdarray) throws IOException {
		Process proc = Runtime.getRuntime().exec(cmdarray, null, Loader.cwd);
		return proc;
	}
}
