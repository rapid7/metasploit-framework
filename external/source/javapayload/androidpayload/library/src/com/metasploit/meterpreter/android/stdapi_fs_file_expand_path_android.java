package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.stdapi.stdapi_fs_file_expand_path;

public class stdapi_fs_file_expand_path_android extends stdapi_fs_file_expand_path {

	protected String getShellPath() {
		return "sh";
	}
}
