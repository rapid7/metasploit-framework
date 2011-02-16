require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers

class WorkstationDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(location, credentials=nil)
		@location = filter_input(location)

		if !File.exist?(@location)
			raise ArgumentError,"Couldn't find: " + location
		end

		@credentials = filter_input_credentials(credentials)

		@type = "workstation"
		
	end

	def start
		system_command("vmrun -T ws start " + "\"#{@location}\"")
	end

	def stop
		system_command("vmrun -T ws stop " + "\"#{@location}\"")
	end

	def suspend
		system_command("vmrun -T ws suspend " + "\"#{@location}\"")
	end

	def pause
		system_command("vmrun -T ws pause " + "\"#{@location}\"")
	end

	def reset
		system_command("vmrun -T ws reset " + "\"#{@location}\"")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("vmrun -T ws snapshot " + "\"#{@location}\" \"#{snapshot}\"")
	end

	def revert_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("vmrun -T ws revertToSnapshot " + "\"#{@location}\" \"#{snapshot}\"")
	end

	def delete_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("vmrun -T ws deleteSnapshot " + "\"#{@location}\" \"#{snapshot}\"" )
	end

	def run_command(command, named_user=nil)
	
		command = filter_input(command)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_creds(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']
	
		vmrunstr = "vmrun -T ws -gu \"{user}\" -gp \"{pass}\" runProgramInGuest \"#{@location}\" \"{command}\" -noWait -activeWindow"

		system_command(vmrunstr)
	end
	
	def copy_from(from, to, named_user=nil)

		from = filter_input(from)
		to = filter_input(to)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_creds(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']
		
		vmrunstr = "vmrun -T ws -gu {user} -gp {pass} copyFileFromGuestToHost \"#{@location}\" \"{from}\" \"{to}\"" 
		system_command(vmrunstr)
	end

	def copy_to(from, to, named_user=nil)
	
		from = filter_input(from)
		to = filter_input(to)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_creds(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']

	
		vmrunstr = "vmrun -T ws -gu {user} -gp {pass} copyFileFromHostToGuest \"#{@location}\" \"{from}\" \"{to}\""  
		system_command(vmrunstr)
	end

	def check_file_exists(file, named_user=nil)
	
		file = filter_input(file)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_creds(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']

	
		vmrunstr = "vmrun -T ws -gu {user} -gp {pass} fileExistsInGuest \"#{@location}\" \"{file}\" "
		system_command(vmrunstr)
	end

	def create_directory(directory, named_user=nil)
	
		directory = filter_input(directory)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_creds(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']
	
		vmrunstr = "vmrun -T ws -gu {user} -gp {pass} createDirectoryInGuest \"#{@location}\" \"#{directory}\" "
		system_command(vmrunstr)
	end

	def cleanup

	end

	def running?
		## Get running Vms
		running = `vmrun list`
		running_array = running.split("\n")
		running_array.shift

		running_array.each do |vmx|
			if vmx.to_s == @location.to_s
				return true
			end
		end

		return false
	end

end

end 
end
