#!/usr/bin/env ruby

require 'pathname'
require 'ruby_smb'

# we just need *a* default encoding to handle the strings from the NTLM messages
Encoding.default_internal = 'UTF-8' if Encoding.default_internal.nil?

options = RubySMB::Server::Cli.parse(defaults: { share_path: '.', username: 'metasploit' }) do |options, parser|
  parser.banner = <<~EOS
    Usage: #{File.basename(__FILE__)} [options]

    Start a read-only SMB file server.

    Options:
  EOS

  parser.on("--share-path SHARE_PATH", "The path to share (default: #{options[:share_path]})") do |path|
    options[:share_path] = path
  end
end

server = RubySMB::Server::Cli.build(options)
server.add_share(RubySMB::Server::Share::Provider::Disk.new(options[:share_name], options[:share_path]))

RubySMB::Server::Cli.run(server)
