package com.metasploit.meterpreter.stdapi;

import java.io.File;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.ExtensionLoader;

/**
 * Loader class to register all the stdapi commands.
 * 
 * @author mihi
 */
public class Loader implements ExtensionLoader {

	public static File cwd;
	
	public static File expand(String path) {
		File result = new File(path);
		if (!result.isAbsolute())
			result = new File(cwd, path);
		return result;
	}

	public void load(CommandManager mgr) throws Exception {
		cwd = new File(".").getCanonicalFile();
		mgr.registerCommand("channel_create_stdapi_fs_file", channel_create_stdapi_fs_file.class);
		mgr.registerCommand("channel_create_stdapi_net_tcp_client", channel_create_stdapi_net_tcp_client.class);
		mgr.registerCommand("channel_create_stdapi_net_tcp_server", channel_create_stdapi_net_tcp_server.class);
		mgr.registerCommand("channel_create_stdapi_net_udp_client", channel_create_stdapi_net_udp_client.class);
		mgr.registerCommand("stdapi_fs_chdir", stdapi_fs_chdir.class);
		mgr.registerCommand("stdapi_fs_delete_dir", stdapi_fs_delete_dir.class);
		mgr.registerCommand("stdapi_fs_delete_file", stdapi_fs_delete_file.class);
		mgr.registerCommand("stdapi_fs_file_expand_path", stdapi_fs_file_expand_path.class, V1_2, V1_5); // %COMSPEC% only
		mgr.registerCommand("stdapi_fs_getwd", stdapi_fs_getwd.class);
		mgr.registerCommand("stdapi_fs_ls", stdapi_fs_ls.class);
		mgr.registerCommand("stdapi_fs_mkdir", stdapi_fs_mkdir.class);
		mgr.registerCommand("stdapi_fs_search", stdapi_fs_search.class);
		mgr.registerCommand("stdapi_fs_separator", stdapi_fs_separator.class);
		mgr.registerCommand("stdapi_fs_stat", stdapi_fs_stat.class, V1_2, V1_6);
		mgr.registerCommand("stdapi_net_config_get_interfaces", stdapi_net_config_get_interfaces.class, V1_4, V1_6);
		mgr.registerCommand("stdapi_net_config_get_routes", stdapi_net_config_get_routes.class, V1_4);
		mgr.registerCommand("stdapi_net_socket_tcp_shutdown", stdapi_net_socket_tcp_shutdown.class, V1_2, V1_3);
		mgr.registerCommand("stdapi_sys_config_getuid", stdapi_sys_config_getuid.class);
		mgr.registerCommand("stdapi_sys_config_sysinfo", stdapi_sys_config_sysinfo.class);
		mgr.registerCommand("stdapi_sys_process_execute", stdapi_sys_process_execute.class, V1_2, V1_3);
		mgr.registerCommand("stdapi_sys_process_get_processes", stdapi_sys_process_get_processes.class, V1_2);
		mgr.registerCommand("stdapi_ui_desktop_screenshot", stdapi_ui_desktop_screenshot.class, V1_4);
		mgr.registerCommand("webcam_audio_record", webcam_audio_record.class, V1_4);
	}
}
