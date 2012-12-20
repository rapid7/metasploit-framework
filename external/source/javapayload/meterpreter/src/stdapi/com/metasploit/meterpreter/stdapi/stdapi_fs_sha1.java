package com.metasploit.meterpreter.stdapi;

public class stdapi_fs_sha1 extends HashCommand {
	protected String getAlgorithm() {
		return "SHA-1";
	}
}
