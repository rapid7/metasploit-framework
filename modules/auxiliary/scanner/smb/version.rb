require 'msf/core'

module Msf

class Auxiliary::Scanner::Smb::Version < Msf::Auxiliary

	# Exploit mixins should be called first
	include Exploit::Remote::SMB
	
	# Scanner mixin should be near last
	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'SMB Version Detection',
			'Version'     => '$Revision: 3624 $',
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
		# print_status("Working on host #{ip}")
		
		[[139, false], [445, true]].each do |info|

		@target_port = info[0]
		datastore['SMBDirect'] = info[1]
		
		begin
			connect()
			smb_login()

			os = 'Unknown'
			sp = ''
	
			case smb_peer_os()
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
				when 'Unix'
					os = 'Unix'
					sv = smb_peer_lm()
					case sv
						when /Samba\s+(.*)/i
							sp = 'Samba v' + $1
					end
			end

			if (os == 'Windows XP' and sp.length == 0)
				# SRVSVC was blocked in SP2
				begin
					smb_create("\\SRVSVC")
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
					smb_create("\\LLSRPC")
					sp = 'Service Pack 0 - Service Pack 4'
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
					if (e.error_code == 0xc0000022)
						sp = 'Service Pack 4 with MS05-010+'
					end
				end
			end
			
 			print_status("#{ip} is running #{os} #{sp}")
			disconnect()

			return
		rescue
			p $!
			p $!.backtrace
		end
		end
	end

end
end
