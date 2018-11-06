#!/usr/bin/ruby

# This example script is used for testing directory listing functionality
# It will attempt to connect to a specific share and then list all files in a
#  specified directory..
# Example usage: ruby list_directory.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE subdir1
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials,
# and then list the contents of the directory 'subdir1'

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
share    = ARGV[3]
dir      = ARGV[4]
path     = "\\\\#{address}\\#{share}"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: username, password: password)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

begin
  tree = client.tree_connect(path)
  puts "Connected to #{path} successfully!"
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

files = tree.list(directory: dir)

files.each do |file|
  create_time = file.create_time.to_datetime.to_s
  access_time = file.last_access.to_datetime.to_s
  change_time = file.last_change.to_datetime.to_s
  file_name   = file.file_name.encode('UTF-8')

  puts "FILE: #{file_name}\n\tSIZE(BYTES):#{file.end_of_file}\n\tSIZE_ON_DISK(BYTES):#{file.allocation_size}\n\tCREATED:#{create_time}\n\tACCESSED:#{access_time}\n\tCHANGED:#{change_time}\n\n"
end
