#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This tool asks Google for the location of a given set of BSSIDs
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..','lib')))
require 'rex/google/geolocation'
require 'optparse'

if ARGV.length < 2
  $stderr.puts("Usage: #{$PROGRAM_NAME} <api_key> <mac> [mac] ...")
  $stderr.puts("Ask Google for the location of the given set of BSSIDs")
  $stderr.puts
  $stderr.puts("Example: iwlist sc 2>/dev/null|awk '/Address/{print $5}'|xargs #{$PROGRAM_NAME} <api_key>")
  $stderr.puts("Example: /System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport -I|awk '/BSSID/{print $2}'|xargs #{$PROGRAM_NAME} <api_key>")
  exit(1)
end

g = Rex::Google::Geolocation.new
g.set_api_key(ARGV[0])
ARGV.drop(1).each do |mac|
  g.add_wlan(mac, -83)
end

g.fetch!

puts g, g.google_maps_url
