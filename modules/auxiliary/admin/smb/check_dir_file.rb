##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants


	def initialize
		super(
			'Name'        => 'SMB Scanner Check File/Directory Utility',
			'Version'     => '$Revision$',
			'Description' => %Q{
				This module is useful when checking an entire network
				of SMB hosts for the presence of a known file or directory.
				An example would be to scan all systems for the presence of
				antivirus or known malware outbreak. Typically you must set
				RPATH, SMBUser, SMBDomain and SMBPass to operate correctly.
			},
			'Author'      =>
				[
					'patrick',
				],
			'References'  =>
				[
				],
			'License'     => MSF_LICENSE
		)

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of an accessible share on the server', 'C$']),
			OptString.new('RPATH', [true, 'The name of the remote file/directory relative to the share'])
		], self.class)

	end

	def run_host(ip)

		if (datastore['VERBOSE'])
			print_status("Connecting to the server...")
		end

		begin
		connect()
		smb_login()

		if (datastore['VERBOSE'])
			print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
		end
		self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

		if (datastore['VERBOSE'])
			print_status("Checking for file/folder #{datastore['RPATH']}...")
		end

		if (fd = simple.open("\\#{datastore['RPATH']}", 'o')) # mode is open only - do not create/append/write etc
			print_good("File FOUND: \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}")
			fd.close
		end
		rescue ::Rex::HostUnreachable
			if (datastore['VERBOSE'])
				print_error("Host #{rhost} offline.")
			end
		rescue ::Rex::Proto::SMB::Exceptions::LoginError
			if (datastore['VERBOSE'])
				print_error("Host #{rhost} login error.")
			end
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
			if e.get_error(e.error_code) == "STATUS_FILE_IS_A_DIRECTORY"
				print_good("Directory FOUND: \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}")
			elsif e.get_error(e.error_code) == "STATUS_OBJECT_NAME_NOT_FOUND"
				if (datastore['VERBOSE'])
					print_error("Object \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']} NOT found!")
				end
			elsif e.get_error(e.error_code) == "STATUS_OBJECT_PATH_NOT_FOUND"
				if (datastore['VERBOSE'])
					print_error("Object PATH \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']} NOT found!")
				end
			elsif e.get_error(e.error_code) == "STATUS_ACCESS_DENIED"
				if (datastore['VERBOSE'])
					print_error("Host #{rhost} reports access denied.")
				end
			elsif e.get_error(e.error_code) == "STATUS_BAD_NETWORK_NAME"
				if (datastore['VERBOSE'])
					print_error("Host #{rhost} is NOT connected to #{datastore['SMBDomain']}!")
				end
			elsif e.get_error(e.error_code) == "STATUS_INSUFF_SERVER_RESOURCES"
				if (datastore['VERBOSE'])
					print_error("Host #{rhost} rejected with insufficient resources!")
				end
			else
				raise e
			end
		end
	end

end


