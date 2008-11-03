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
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::DCERPC
	
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'Microsoft Server Service MS08-067 Patch Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module scans one or more systems for the presence of the
			MS08-067 patch for the Server Service. The technique used by this
			module was borrowed from ms08-067_check.py, a tool written by
			Bernardo Damele A. G. <bernardo.damele[at]gmail.com>.
			},
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		
		deregister_options('RPORT', 'RHOST')
		register_options(
			[
				OptString.new('SMBPIPE', [ true,  "The pipe name to use (BROWSER)", 'BROWSER']),
			], self.class)		
	end

	#
	# This method is based on the python script:  http://labs.portcullis.co.uk/download/ms08-067_check.py
	# There are two problems with this method:
	#   1. It can sometimes lead to a crash of svchost.exe due to a race condition
	#	2. The Python script may be based on a Nessus plugin, which violates the Tenable license
	# 

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

			tpath  = Rex::Text.rand_text_alpha(1).downcase
			handle = dcerpc_handle(
				'4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0', 
				'ncacn_np', ["\\#{datastore['SMBPIPE']}"]
			)

			dcerpc_bind(handle)

			vuln = Exploit::CheckCode::Safe

			stub = 
				NDR.uwstring("") +
				NDR.wstring( "\\"+ ("A" * 39) + "\\..\\#{tpath}") +
				NDR.wstring("\\#{tpath}") +
				NDR.long(1) +
				NDR.long(0)		

			begin
				dcerpc.call(0x20, stub)
				buff = dcerpc.last_response.stub_data
				
				if(buff and buff.length == 4)
					if(buff[0,4] == "\x00\x00\x00\x00")
						vuln = Exploit::CheckCode::Vulnerable
					else
						vuln = Exploit::CheckCode::Safe
					end
				end
			end

			case vuln
			when Exploit::CheckCode::Vulnerable
				print_status("#{rhost} (MS08-067) VULNERABLE")
			when Exploit::CheckCode::Safe
				print_status("#{rhost} (MS08-067) PATCHED")
			end			
			
			disconnect()

			rescue ::Interrupt 
				raise $!
			rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
			rescue ::Rex::Proto::SMB::Exceptions::LoginError
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Exception => e
				print_error("Error: #{e.class} #{e} #{e.backtrace}")
		end
		end
	end
	

end
