#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script takes a list of ranges and converts it to a per line IP list.
# Demonstration:
# echo 192.168.100.0-50 >> rangelist.txt
# echo 192.155-156.0.1 >> rangelist.txt
# echo 192.168.200.0/25 >> rangelist.txt
# ruby tools/recon/makeiplist.rb
#
# Author:
# mubix
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

require 'msfenv'
require 'rex'
require 'optparse'

class OptsConsole
  def self.parse(args)
    options = {}

    opts = OptionParser.new do |opts|
      opts.banner = %Q|This script takes a list of ranges and converts it to a per line IP list.
Usage: #{__FILE__} [options]|

      opts.separator ""
      opts.separator "Specific options:"

      opts.on("-i", '-i <filename>', "Input file") do |v|
        options['input'] = v.to_s
      end

      opts.on("-o", '-o <filename>', "(Optional) Output file. Default: iplist.txt") do |v|
        options['output'] = v.to_s
      end

      opts.separator ""
      opts.separator "Common options:"

      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
    end

    opts.parse!(args)
    if options.empty?
      puts "[*] No options specified, try -h for usage"
      exit
    end

    begin
      if options['input'] == nil
        puts opts
        raise OptionParser::MissingArgument, '-i is a required argument'
      end
      unless ::File.exist?(options['input'])
        raise OptionParser::InvalidArgument, "Not found: #{options['input']}"
      end
      if options['output'] == nil
        options['output'] = 'iplist.txt'
      end
    rescue OptionParser::InvalidOption
      puts "[*] Invalid option, try -h for usage"
      exit
    rescue OptionParser::InvalidArgument => e
      puts "[*] #{e.message}"
      exit
    end

    options
  end
end

#
# Prints IPs
#
def make_list(in_f, out_f)
  in_f.each_line do |range|
    ips = Rex::Socket::RangeWalker.new(range)
    ips.each do |ip|
      out_f.puts ip
      end
    end
end

#
# Returns file handles
#
def load_files(in_f, out_f)
  handle_in = ::File.open(in_f, 'r')

  # Output file not found, assuming we should create one automatically
  ::File.open(out_f, 'w') {} unless ::File.exist?(out_f)

  handle_out = ::File.open(out_f, 'a')

  return handle_in, handle_out
end

options = OptsConsole.parse(ARGV)
in_f, out_f = load_files(options['input'], options['output'])

begin
  puts "[*] Generating list at #{options['output']}"
  make_list(in_f, out_f)
ensure
  # Always makes sure the file descriptors are closed
  in_f.close
  out_f.close
end

puts "[*] Done."
