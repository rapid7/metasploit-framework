require 'vm_driver'

##
## $Id$
##

# This driver was built against: 
# VMware ESX Host Agent 4.1.0 build-348481

module Lab
module Drivers

class RemoteEsxDriver < VmDriver

	def initialize(config)

		unless config['user'] then raise ArgumentError, "Must provide a username" end
		unless config['host'] then raise ArgumentError, "Must provide a hostname" end

		super(config)

		@user = filter_command(config['user'])
		@host = filter_command(config['host'])
	end

	def start
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.on #{@vmid}\"")
	end

	def stop
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.off #{@vmid}\"")
	end

	def suspend
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspend #{@vmid}\"")
	end

	def pause 	# no concept of pause?
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspend #{@vmid}\"")
	end

	def resume
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.suspendResume #{@vmid}\"")
	end

	def reset
		system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.reset #{@vmid}\"")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		
		#vmware-vim-cmd vmsvc/snapshot.create [vmid: int] [snapshotName: string] 
		#			[snapshotDescription: string] [includeMemory:bool]

		`ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.create #{@vmid} #{snapshot} \'lab created snapshot\' 1 true\""`
	end

	def revert_snapshot(snapshot)
		raise "Not Implemented"



		#vmware-vim-cmd vmsvc/snapshot.revert [vmid: int] [snapshotlevel: int] [snapshotindex: int]
		# not sure how we can do this, would have to list snapshots and map name to level & index

		#snapshot = filter_input(snapshot)
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.revert #{@vmid} 0 0\"")
	end

	def delete_snapshot(snapshot)
		raise "Not Implemented"

		#snapshot = filter_input(snapshot)
		#system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.remove #{@vmid} true 0 0\"")
	end
	
	def run_command(command)
		raise "Not Implemented"
	end
	
	def copy_from(from, to)
		if @os == "linux"
			scp_from(from, to)
		else
			raise "Unimplemented"
		end
	end

	def copy_to(from, to)
		if @os == "linux"
			scp_to(from, to)
		else
			raise "Unimplemented"
		end
	end

	def check_file_exists(file)
		raise "Not Implemented"
	end

	def create_directory(directory)
		raise "Not Implemented"
	end

	def cleanup

	end

	def running?
		power_status_string = `ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.getstate #{@vmid}\"`
		return true if power_status_string =~ /Powered on/
	false
	end

end

end 
end
