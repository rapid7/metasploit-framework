##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TNS

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'tnscmd - a lame tool to prod the oracle tnslsnr process.',
			'Description'    => %q{
				Inspired from tnscmd.pl from www.jammed.com/~jwa/hacks/security/tnscmd/tnscmd
			},
			'Author'         => ['MC'],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'DisclosureDate' => 'Feb 1 2009'))

                        register_options( 
                                [
					Opt::RPORT(1521),
					OptString.new('CMD', [ false, 'Something like ping, version, status, etc..', '(CONNECT_DATA=(COMMAND=VERSION))']),
                                ], self.class)

	end

	def run
		connect

		command = datastore['CMD']

		pkt = tns_packet(command)

		print_status("Sending '#{command}' to #{rhost}:#{rport}")
		sock.put(pkt)
		print_status("writing #{pkt.length} bytes.")
		
		sleep(0.5)

		print_status("reading")
		res = sock.get_once(-1,5)
		puts res

		disconnect		
	end
end
