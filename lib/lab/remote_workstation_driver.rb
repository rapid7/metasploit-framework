require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers

class RemoteWorkstationDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(location, user=nil, host=nil, credentials=nil)

		## TODO - Should proabably check file existence?	

		unless user then raise ArgumentError, "Must provide a username" end
		unless host then raise ArgumentError, "Must provide a hostname" end
		
		@location = filter_input(location)
		@user = filter_input(user)
		@host = filter_input(host)
		@credentials = filter_input_credentials(credentials)
		@type = "remote_workstation"
	end

	def start
		system_command("ssh #{@user}@#{@host} vmrun -T ws start \\\'#{@location}\\\' nogui")
	end

	def stop
		system_command("ssh #{@user}@#{@host} vmrun -T ws stop \\\'#{@location}\\\' nogui")
	end

	def suspend
		system_command("ssh #{@user}@#{@host} vmrun -T ws suspend \\\'#{@location}\\\' nogui")
	end

	def pause
		system_command("ssh #{@user}@#{@host} vmrun -T ws pause \\\'#{@location}\\\' nogui")
	end

	def reset
		system_command("ssh #{@user}@#{@host} vmrun -T ws reset \\\'#{@location}\\\' nogui")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws snapshot \\\'#{@location}\\\' #{snapshot} nogui")
	end

	def revert_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws revertToSnapshot \\\'#{@location}\\\' #{snapshot} nogui")
	end

	def delete_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws deleteSnapshot \\\'#{@location}\\\' #{snapshot} nogui" )
	end


	def run_command(command, named_user=nil)
	
		command = filter_input(command)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_creds(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']
	
		vmrunstr = "ssh #{@user}@#{@host} vmrun -T ws -gu \\\'{user}\\\' -gp \\\'{pass}\\\' runProgramInGuest \\\'#{@location}\\\' \\\'{command}\\\' -noWait -activeWindow nogui"

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
		
		vmrunstr = "ssh #{@user}@#{@host}  vmrun -T ws -gu {user} -gp {pass} copyFileFromGuestToHost \\\'#{@location}\\\' \\\'{from}\\\' \\\'{to}\\\' nogui" 
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

	
		vmrunstr = "ssh #{@user}@#{@host}  vmrun -T ws -gu {user} -gp {pass} copyFileFromHostToGuest \\\'#{@location}\\\' \\\'{from}\\\' \\\'{to}\\\' nogui"  
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

	
		vmrunstr = "ssh #{@user}@#{@host} vmrun -T ws -gu {user} -gp {pass} fileExistsInGuest \\\'#{@location}\\\' \\\'{file}\\\' nogui"
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
	
		vmrunstr = "ssh #{@user}@#{@host} vmrun -T ws -gu {user} -gp {pass} createDirectoryInGuest \\\'#{@location}\\\' \\\'#{directory}\\\' nogui"
		system_command(vmrunstr)
	end


	def cleanup

	end

	def running?
		## Get running Vms
		running = `ssh #{@user}@#{@host} vmrun list nogui`
		running_array = running.split("\n")
		running_array.shift

		running_array.each do |vmx|
			if vmx.to_s == @location.to_s
				return true
			end
		end

		false
	end

end

end 
end
