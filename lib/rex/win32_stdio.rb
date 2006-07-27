#!/usr/bin/env ruby


require 'dl'
require 'socket'

$:.push(File.dirname(__FILE__))
require 'compat'

port = ARGV.shift() || exit(0)


# This script is used to provide async stdio on Windows
begin
	sock = TCPSocket.new('127.0.0.1', port)

	Rex::Compat.win32_stdin_unblock()

	$stderr.puts "Starting stdio daemon..."
	
	while (true)
		c = $stdin.sysread(1)
		$stderr.printf("%.2x \n", c[0])
		sock.write(c)
		sock.flush
	end
rescue ::Exception
	$stderr.puts "Exception: #{$!.to_s}"
end

Rex::Compat.win32_stdin_block()
