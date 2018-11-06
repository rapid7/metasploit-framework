#!/usr/bin/ruby

# This example script is used for testing NetShareEnumAll functionality
# It will attempt to connect to a host and enumerate shares.
# Example usage: ruby net_share_enum_all.rb 192.168.172.138 msfadmin msfadmin
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentials

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
path     = "\\\\#{address}\\IPC$"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: username, password: password)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

begin
  shares = client.net_share_enum_all(address)
  puts shares
rescue => e
  puts "failed to enum shares: #{e.message}, #{e.backtrace_locations}"
end

client.disconnect!

