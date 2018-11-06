#!/usr/bin/ruby

#
# This script is for testing the Protocol Negotiation in the library
# without any other parts.

require 'bundler/setup'
require 'ruby_smb'

def run_negotiation(address, smb1, smb2)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, username: 'msfadmin', password: 'msfadmin')
  client.negotiate
end

# Negotiate with both SMB1 and SMB2 enabled on the client
run_negotiation(ARGV[0], true, true)
# Negotiate with only SMB1 enabled
run_negotiation(ARGV[0], true, false)
# Negotiate with only SMB2 enabled
run_negotiation(ARGV[0], false, true)
