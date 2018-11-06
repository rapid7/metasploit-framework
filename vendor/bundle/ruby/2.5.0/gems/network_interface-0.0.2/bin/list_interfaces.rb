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

begin
  require 'network_interface'
rescue ::Exception => e
  $stderr.puts "Error: NetworkInterface is not installed..."
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
  if detail
    puts "NAME         :  " + detail["name"]
    puts "DESCRIPTION  :  " + detail["description"]
    puts "GUID         :  " + detail["guid"]
  else
    puts "NAME         :  " + iface
  end
  if addr[NetworkInterface::AF_LINK][0]['addr']
    puts "MAC ADDRESS  :  #{addr[NetworkInterface::AF_LINK][0]['addr']}"
  else
    puts "MAC ADDRESS  :  NONE"
  end
  if addr && addr[NetworkInterface::AF_INET]
    addr[NetworkInterface::AF_INET].each do |ip4|
      puts "IP ADDRESS   :  #{ip4['addr']}/#{ip4['netmask']}"
    end
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
