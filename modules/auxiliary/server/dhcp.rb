##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex/proto/dhcp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::DHCPServer
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'DHCP File Server',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module provides a DHCP service
			},
			'Author'      => [ 'scriptjunkie' ],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Capture' ]
				],
			'PassiveActions' =>
				[
					'Capture'
				],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptString.new('SRVHOST',   [ true,  "The IP of the DHCP server" ]),
				OptString.new('NETMASK',   [ true,  "The netmask of the local subnet" ]),
				OptString.new('DHCPIPSTART',   [ false,  "The first IP to give out" ]),
				OptString.new('DHCPIPEND',   [ false,  "The last IP to give out" ]),
				OptString.new('ROUTER',   [ false,  "The router IP address" ]),
				OptString.new('DNSSERVER',   [ false,  "The DNS server IP address" ]),
				OptString.new('FILENAME',   [ false,  "The optional filename of a tftp boot server" ])
			], self.class)
	end

	def run
		@dhcp = Rex::Proto::DHCP::Server.new(datastore)

		print_status("Starting DHCP server...")
		@dhcp.start

		# Wait for finish..
		@dhcp.thread.join
	end

end

