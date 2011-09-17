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

		snapshots = get_snapshots
		
		# Look through our snapshot list, choose the right one based on display_name		
		snapshots.each do |snapshot_obj|
			if snapshot_obj[:display_name].downcase == snapshot.downcase
				snapshot_number = snapshot_obj[:name].join(" ")
				system_command("ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.revert #{@vmid} #{snapshot_number}\"")
				return true
			end
		end
	
		# If we got here, the snapshot didn't exist
		raise "Invalid Snapshot Name"
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

private 

	def get_snapshots
		# Command take the format: 
		# vmware-vim-cmd vmsvc/snapshot.revert [vmid: int] [snapshotlevel: int] [snapshotindex: int]
		output = `ssh #{@user}@#{@host} \"vim-cmd vmsvc/snapshot.get #{@vmid}\"`

		# this keeps track of the snapshots, takes the form:
		#[ {:name => [0,0], :display_name => "String containing the snapshotname}, 
		#  {:name => [0,1], :display_name => "String containing the snapshotname}, ]
		#  ... 
		snapshots = []
		
		# Use these to keep track of the parsing...		
		current_tree = -1
		current_num = 0
		count = 0
		
		# Do the parsing & stick the snapshots in the snapshots array
		output_lines = output.split("\n")
		output_lines.each do |line|
			if line.include?("|") # this is a new snapshot
				if line.include?("ROOT") # it's a root
					current_tree = current_tree + 1 # new tree
					snapshots << { :name => [current_tree,current_num], :display_name => output_lines[count+1].split(":").last.strip }
					current_num = 0
				else
					current_num = current_num + 1 # new snapshot in current tree
					snapshots << { :name => [current_tree,current_num], :display_name => output_lines[count+1].split(":").last.strip }
				end
			end
			count = count+1
		end

	snapshots
	end

end

end 
end
