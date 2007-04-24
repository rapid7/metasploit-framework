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

module Msf

class Auxiliary::Scanner::Smb::Version < Msf::Auxiliary

	
	# Exploit mixins should be called first
	include Exploit::Remote::Tcp
	
	# We can't use SMB here, since the SMB mixin
	# is not thread-safe and will not become so
	# without a ton of work (self.sock, etc).
	
	# Scanner mixin should be near last
	include Auxiliary::Scanner

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

	# Fingerprint a single host
	def run_host(ip)

		[[139, false], [445, true]].each do |info|

		self.target_port = info[0]
		direct = info[1]
		
		soc = nil 
		
		begin
			# print_status("Trying to connect to #{target_host()}:#{target_port()}...")
			soc = connect(false)
			smb = SIMPLE.new(soc, direct)
			
			smb.login('*SMBSERVER')

			smb.connect('IPC$')
			
			os = 'Unknown'
			sp = ''

			case smb.client.peer_native_os
				when 'Windows NT 4.0'
					os = 'Windows NT 4.0'
				when 'Windows 5.0'
					os = 'Windows 2000'
				when 'Windows 5.1'
					os = 'Windows XP'
				when /Windows Server 2003 (\d+)$/
					os = 'Windows 2003'
					sp = 'No Service Pack'
				when /Windows Server 2003 (\d+) Service Pack (\d+)/
					os = 'Windows 2003'
					sp = 'Service Pack ' + $2
				when /Windows Vista \(TM\) (\w+) (\d+)/
					os = 'Windows Vista ' + $1
					sp = '(Build ' + $2 + ')'
				when 'Unix'
					os = 'Unix'
					sv = smb.client.peer_native_lm
					case sv
						when /Samba\s+(.*)/i
							sp = 'Samba ' + $1
					end
			end

			if (os == 'Windows XP' and sp.length == 0)
				# SRVSVC was blocked in SP2
				begin
					smb.create_pipe("\\SRVSVC")
					sp = 'Service Pack 0 / Service Pack 1'
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
					if (e.error_code == 0xc0000022)
						sp = 'Service Pack 2+'
					end
				end
			end
			
			if (os == 'Windows 2000' and sp.length == 0)
				# LLSRPC was blocked in a post-SP4 update
				begin
					smb.create_pipe("\\LLSRPC")
					sp = 'Service Pack 0 - Service Pack 4'
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
					if (e.error_code == 0xc0000022)
						sp = 'Service Pack 4 with MS05-010+'
					end
				end
			end
			
 			print_status("#{ip} is running #{os} #{sp}")
			
			if (os == 'Unknown') 
				print_status("NativeOS: #{smb.client.peer_native_os()}")
				print_status("NativeLM: #{smb.client.peer_native_lm()}")
			end
			
			return

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			next
		
		# rescue => e
		#	p e.class
		#	p e.to_s

		ensure
			soc.close if soc
			soc = nil
						
		end
		end
	end

end
end
