#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#
# This small utility will display all the informations about the network interfaces
# that one can use under Windows with modules using pcaprub and having the INTERFACE option (ex: arp_poisonning, arp_sweep, ...).
# To use th interface option under  Windows use the Index value displayed by this tool (ex: "SET INTERFACE 1")
#
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']


if RUBY_PLATFORM == "i386-mingw32"
  begin
    require 'network_interface'
  rescue ::Exception => e
    $stderr.puts "Error: NetworkInterface is not installed..."
    exit
  end

  unless (
    NetworkInterface.respond_to?(:interfaces) and
    NetworkInterface.respond_to?(:addresses)  and
    NetworkInterface.respond_to?(:interface_info)
  )
    $stderr.puts "Error: Looks like you are not running the latest version of NetworkInterface"
    exit
  end
  found = false
  NetworkInterface.interfaces.each_with_index do |iface, i|
    found = true
    detail = NetworkInterface.interface_info(iface)
    addr = NetworkInterface.addresses(iface)
    puts "#" * 70
    puts ""
    puts "INDEX        :  " + (i + 1).to_s
    puts "NAME         :  " + detail["name"]
    puts "DESCRIPTION  :  " + detail["description"]
    puts "GUID         :  " + detail["guid"]
    if addr[NetworkInterface::AF_LINK][0]['addr']
      puts "MAC ADDRESS  :  #{addr[NetworkInterface::AF_LINK][0]['addr']}"
    else
      puts "MAC ADDRESS  :  NONE"
    end
    if addr[NetworkInterface::AF_INET][0]['addr'] and addr[NetworkInterface::AF_INET][0]['netmask']
      puts "IP ADDRESS   :  #{addr[NetworkInterface::AF_INET][0]['addr']}/#{addr[NetworkInterface::AF_INET][0]['netmask']}"
    else
      puts "IP ADDRESS   :  NONE"
    end
    puts ""
  end
  if found
    puts "#" * 70
  else
    $stderr.puts "Error, no network interfaces have been detected"
  end
else
  $stderr.puts "Error: This script is useful only on Windows, under other OS just use the built-in commands (ifconfig, ip link show, ...)"
  exit
end
