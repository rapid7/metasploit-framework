#!/usr/bin/ruby

$: << 'lib' << '../lib' << '../../lib'

require 'socket'
reqiure 'rex'
require 'Rex/Post/Meterpreter'

if(ARGV.length != 2)
	puts "usage: <ip> <port>"
	exit(1)
end

sock = TCPSocket.new(ARGV[0], ARGV[1])

c = Rex::Post::Meterpreter::Client.new(sock)

c.core.use('Stdapi')

@c = c

irb
