##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Foo module',
			'Description'    => %q{
				This module demos a bug.
			},
			'Author'         => [ 'todb' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '1234' ]
				],
			'DisclosureDate' => 'Oct 04 2009'))

			register_options(
				[
					OptAddress.new('LHOST', [true, "The spoofed address of a vulnerable ntpd server" ])
				], self.class)

			deregister_options('FILTER','PCAPFILE')

	end

	def run
		this_array = Array.new
		this_array << "bug"
		print_status this_array.join
	end

end
