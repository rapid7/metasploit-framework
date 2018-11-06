#!/usr/bin/ruby

#
# Example script for connecting to a named pipe and performing a peek operation.
# This is used to demonstrate pipe operations.
#
# Usage: ruby pipes.rb ADDRESS PIPENAME USER PASS 1|2
#

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
pipename = ARGV[1]
username = ARGV[2]
password = ARGV[3]
smbver   = ARGV[4].to_i

sock = TCPSocket.new(address, 445)
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

if smbver == 2
  client = RubySMB::Client.new(dispatcher, smb1: false, username: username, password: password)
  client.negotiate
  puts "ServerMaxRead:   #{client.server_max_read_size}"
  puts "ServerMaxWrite:  #{client.server_max_write_size}"
  puts "ServerMaxTrans:  #{client.server_max_transact_size}"
elsif smbver == 1
  client = RubySMB::Client.new(dispatcher, smb2: false, username: username, password: password)
  client.negotiate
  puts "ServerMaxBuffer: #{client.server_max_buffer_size}"
end

client.authenticate
client.tree_connect("\\\\#{address}\\IPC$")
pipe = client.create_pipe(pipename, nil)

puts "Available:       #{pipe.peek_available}"
puts "PipeState:       #{pipe.peek_state}" # 3 == OK
puts "IsConnected:     #{pipe.is_connected?}"

pipe.close
puts "IsConnected:     #{pipe.is_connected?}"
client.tree_connects[-1].disconnect!
client.disconnect!
