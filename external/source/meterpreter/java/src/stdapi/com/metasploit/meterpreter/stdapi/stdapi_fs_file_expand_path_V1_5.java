package com.metasploit.meterpreter.stdapi;

import java.io.File;

public class stdapi_fs_file_expand_path_V1_5 extends stdapi_fs_file_expand_path {

	protected String getShellPath() {
		String result;
		if (File.pathSeparatorChar == ';')
			result = System.getenv("COMSPEC");
		else
			result = System.getenv("SHELL");
		if (result == null || result.length() == 0)
			result = super.getShellPath();
		return result;
	}
}
