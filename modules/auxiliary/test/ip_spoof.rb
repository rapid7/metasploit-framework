##
# $Id: scanner_host.rb 5330 2008-01-23 02:28:12Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'scruby'

module Msf

class Auxiliary::Test::IP_Spoof < Msf::Auxiliary

	include Exploit::Remote::Ip
	include Auxiliary::Scanner
		
	def initialize
		super(
			'Name'        => 'Simple IP Spoofing Tester',
			'Version'     => '$Revision: 5330 $',
			'Description' => 'Simple IP Spoofing Tester',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
	end

	def run_host(ip)
		print_status("Sending a packet to host #{ip}")
		
		connect_ip if not ip_sock
		buff = (
			Scruby::IP.new(
				:src   => ip, 
				:dst   => ip,
				:proto => 17,
				:ttl   => 255,
				:id    => 0xdead
			)/Scruby::UDP.new(
				:sport => 53,
				:dport => 53
			)/"HELLO WORLD"
		).to_net
		
		ip_sock.sendto(buff, ip)
	end

	
end
end
