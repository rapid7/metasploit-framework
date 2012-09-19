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
		require 'pcaprub'
	rescue ::Exception => e
		$stderr.puts "Error: pcaprub is not installed..."
		exit
	end
	unless (Pcap.respond_to?(:lookupaddrs) and
			Pcap.respond_to?(:interfaces) and
			Pcap.respond_to?(:addresses))
		$stderr.puts "Error: Looks like you are not running the latest version of pcaprub"
		exit
	end
	found = false
	Pcap.interfaces.each_with_index do |iface, i|
		found = true
		detail = Pcap.interface_info(iface)
		addr = Pcap.addresses(iface)
		puts "#" * 70
		puts ""
		puts "INDEX        :  " + (i + 1).to_s
		puts "NAME         :  " + detail["name"]
		puts "DESCRIPTION  :  " + detail["description"]
		puts "GUID         :  " + detail["guid"]
		if addr[Pcap::AF_LINK][0]['addr']
			puts "MAC ADDRESSE :  #{addr[Pcap::AF_LINK][0]['addr']}"
		else
			puts "MAC ADDRESSE :  NONE"
		end
		if addr[Pcap::AF_INET][0]['addr'] and addr[Pcap::AF_INET][0]['netmask']
			puts "IP ADDRESSE  :  #{addr[Pcap::AF_INET][0]['addr']}/#{addr[Pcap::AF_INET][0]['netmask']}"
		else
			puts "IP ADDRESSE  :  NONE"
		end
		puts ""
	end
	if found
		puts "#" * 70
	else
		$stderr.puts "Error, no network interfaces have been detected"
	end
else
	$stderr.puts "Error: This script is usefull only on Windows, under other OS just use the built-in commands (ifconfig, ip link show, ...)"
	exit
end


