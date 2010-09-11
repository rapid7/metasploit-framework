package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.ExtensionLoader;

/**
 * Loader class to register all the core commands.
 * 
 * @author mihi
 */
public class Loader implements ExtensionLoader {

	public void load(CommandManager mgr) throws Exception {
		mgr.registerCommand("core_channel_close", core_channel_close.class);
		mgr.registerCommand("core_channel_eof", core_channel_eof.class);
		mgr.registerCommand("core_channel_interact", core_channel_interact.class);
		mgr.registerCommand("core_channel_open", core_channel_open.class);
		mgr.registerCommand("core_channel_read", core_channel_read.class);
		mgr.registerCommand("core_channel_write", core_channel_write.class);
		mgr.registerCommand("core_loadlib", core_loadlib.class);
	}
}
