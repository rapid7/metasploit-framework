##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants

	
	def initialize
		super(
			'Name'        => 'SMB Version Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display version information about each system',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		
		deregister_options('RPORT')
	end

	# Overload the RPORT setting
	def rport
		@target_port
	end

	# Fingerprint a single host
	def run_host(ip)	
		[[139, false], [445, true]].each do |info|

		@target_port = info[0]
		self.smb_direct = info[1]
		
		begin
			connect()
			smb_login()
			
			res = smb_fingerprint()
			
			if(res['os'] and res['os'] != 'Unknown')
				print_status("#{rhost} is running #{res['os']} #{res['sp']} (language: #{res['lang']})")
			else
				print_status("#{rhost} could not be identified")
			end
			
			disconnect
			
			break
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
		rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
			
			# Vista has 139 open but doesnt like *SMBSERVER
			if(e.to_s =~ /server refused our NetBIOS/)
				next
			end
			
			return
		rescue ::Rex::ConnectionError
			next
		rescue ::Exception => e
			print_error("#{rhost}: #{e.class} #{e} #{e.backtrace}")
		ensure
			disconnect
		end
		end
	end

end
