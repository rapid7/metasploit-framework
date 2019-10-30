#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'rex/parser/winscp'

exit unless ARGV.count == 1

include Rex::Parser::WinSCP

puts ARGV.first
read_and_parse_ini(ARGV.first).each do |res|
  puts res.inspect
end
