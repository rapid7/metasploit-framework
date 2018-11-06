#!/usr/bin/ruby

# This script tests a full Authentication/Session Setup cycle
# including protocol negotiation and authentication.

require 'bundler/setup'
require 'ruby_smb'

def run_authentication(address, smb1, smb2, username, password)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, username: username, password: password)
  protocol = client.negotiate
  status = client.authenticate
  puts "#{protocol} : #{status}"
  if status.name == 'STATUS_SUCCESS'
    puts "Native OS: #{client.peer_native_os}"
    puts "Native LAN Manager: #{client.peer_native_lm}"
    puts "Domain/Workgroup: #{client.primary_domain}"
  end
end

address  = ARGV[0]
username = ''
password = ''

# Negotiate with only SMB1 enabled
run_authentication(address, true, false, username, password)
