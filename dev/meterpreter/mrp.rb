#!/usr/bin/env ruby

$: << 'lib' << '../lib' << '../../lib'

require 'socket'
require 'rex'
require 'rex/post/meterpreter'

if(ARGV.length != 2)
	puts "usage: <ip> <port>"
	exit(1)
end

sock = TCPSocket.new(ARGV[0], ARGV[1])

c = Rex::Post::Meterpreter::Client.new(sock)

c.core.use('Stdapi')

@c = c

irb
