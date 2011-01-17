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

		## Can we check file existence?		
		
		#if !File.exist?(location)
		#	raise ArgumentError,"Couldn't find: " + location
		#end

		unless user then raise ArgumentError, "Must provide a username" end
		unless host then raise ArgumentError, "Must provide a hostname" end
		
		@location = location
		@host = host
		@user = user
		@credentials = credentials
		@type = "RemoteWorkstation"
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

	def create(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws snapshot \\\'#{@location}\\\' #{snapshot} nogui")
	end

	def revert(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws revertToSnapshot \\\'#{@location}\\\' #{snapshot} nogui")
	end

	def delete_snapshot(snapshot)
		system_command("ssh #{@user}@#{@host} vmrun -T ws deleteSnapshot \\\'#{@location}\\\' #{snapshot} nogui" )
	end


	def run_command(command, named_user=nil)
	
		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_credentials(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']
	
		vmrunstr = "ssh #{@user}@#{@host} vmrun -T ws -gu \\\'{user}\\\' -gp \\\'{pass}\\\' runProgramInGuest \\\'#{@location}\\\' \\\'{command}\\\' -noWait -activeWindow nogui"

		system_command(vmrunstr)
	end
	
	def copy_from(from, to, named_user=nil)

		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_credentials(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']
		
		vmrunstr = "ssh #{@user}@#{@host}  vmrun -T ws -gu {user} -gp {pass} copyFileFromGuestToHost \\\'#{@location}\\\' \\\'{from}\\\' \\\'{to}\\\' nogui" 
		system_command(vmrunstr)
	end

	def copy_to(from, to, named_user=nil)
	
		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_credentials(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']

	
		vmrunstr = "ssh #{@user}@#{@host}  vmrun -T ws -gu {user} -gp {pass} copyFileFromHostToGuest \\\'#{@location}\\\' \\\'{from}\\\' \\\'{to}\\\' nogui"  
		system_command(vmrunstr)
	end

	def check_file_exists(file, named_user=nil)
	
		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_credentials(named_user)
	
		user = cred['user']
		pass = cred['pass']
		admin = cred['admin']

	
		vmrunstr = "ssh #{@user}@#{@host} vmrun -T ws -gu {user} -gp {pass} fileExistsInGuest \\\'#{@location}\\\' \\\'{file}\\\' nogui"
		system_command(vmrunstr)
	end

	def create_directory(directory, named_user=nil)
	
		## this will return the first user if named_user doesn't exist
		##  -- that may not be entirely obvious...
		cred = get_best_credentials(named_user)
	
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

		return false
	end

end

end 
end
