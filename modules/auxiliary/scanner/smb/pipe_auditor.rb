##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Scanner::Smb::Pipe_Auditor < Msf::Auxiliary

	# Exploit mixins should be called first
	include Exploit::Remote::SMB
	
	# Scanner mixin should be near last
	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'SMB Session Pipe Auditor',
			'Version'     => '$Revision$',
			'Description' => 'Determine what named pipes are accessible over SMB',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		
		deregister_options('RPORT')
	end

	@@target_pipes = [
		'netlogon',
		'lsarpc',
		'samr',
		'browser',
		'atsvc',
		'DAV RPC SERVICE',
		'epmapper',
		'eventlog',
		'InitShutdown',
		'keysvc',
		'lsass',
		'LSM_API_service',
		'ntsvcs',
		'plugplay',
		'protected_storage',
		'router',
		'SapiServerPipeS-1-5-5-0-70123',
		'scerpc',
		'srvsvc',
		'tapsrv',
		'trkwks',
		'W32TIME_ALT',
		'wkssvc',
		'PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER'
	]


	# Overload the RPORT setting
	def rport
		@target_port
	end
	
	# Fingerprint a single host
	def run_host(ip)

		pass = []
		
		[[139, false], [445, true]].each do |info|

		@target_port = info[0]
		datastore['SMBDirect'] = info[1]
		
		begin
			connect()
			smb_login()
			@@target_pipes.each do |pipe|
				begin
					fid = smb_create("\\#{pipe}")
					# print_status("Opened pipe \\#{pipe}")
					pass.push(pipe)
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
					# print_error("Could not open \\#{pipe}: Error 0x%.8x" % e.error_code)
				end
			end
			
			disconnect()

			break
		rescue ::Exception => e
			print_line($!.to_s)
			print_line($!.backtrace.join("\n"))			
		end
		end

		if(pass.length > 0)
			print_status("Pipes: #{pass.map{|c| "\\#{c}"}.join(", ")}")
		end
	end
	

end
end
