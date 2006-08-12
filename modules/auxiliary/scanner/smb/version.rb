require 'msf/core'

module Msf

class Auxiliary::Scanner::Smb::Version < Msf::Auxiliary

	include Auxiliary::Scanner
	include Exploit::Remote::SMB
	
	def initialize
		super(
			'Name'        => 'SMB Version Detection',
			'Version'     => '$Revision: 3624 $',
			'Description' => 'Display version information about each system',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptAddress.new('RHOST',  [ false,  "Ignore me please" ])
			], self.class)	

	end

	def run_host(ip)
		print_status("Working on host #{ip}")
		datastore['RHOST'] = ip
		
		begin
			connect()
			smb_login()
 			print_status("#{ip} OS=#{smb_peer_os()} LM=#{smb_peer_lm()}")
			disconnect()
		
		rescue
		end
		
	end

end
end
