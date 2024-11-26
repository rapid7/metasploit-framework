#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))

require 'openssl'
require 'rex'

require 'rex/post/meterpreter'

ip   = ARGV.shift() || exit
port = ARGV.shift() || 31337

if (ip == nil || port == nil)
  puts "Syntax: test.rb <ip> [port]\n"
  exit
end

sock = TCPSocket.new(ip, port)

puts "* Initializing Meterpreter"

meterp = Rex::Post::Meterpreter::Client.new(sock)

puts "* Loading Stdapi"

meterp.core.use('Stdapi')

puts "* System info:"

p meterp.sys.config.sysinfo

puts "* Closing socket"

meterp.sock.close
