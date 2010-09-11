package com.metasploit.meterpreter.stdapi;

import java.io.File;

public class stdapi_fs_stat_V1_6 extends stdapi_fs_stat {

	protected boolean canExecute(File file) {
		return file.canExecute();
	}
}
