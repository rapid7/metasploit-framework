require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers

class WorkstationDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(vmid, location, credentials=nil)
		@vmid = filter_input(vmid)
		@location = filter_input(location)
		if !File.exist?(@location)
			raise ArgumentError,"Couldn't find: " + @location
		end

		@credentials = credentials

		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user'])
			@vm_pass = filter_input(@credentials[0]['pass'])
		end
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

	def run_command(command)
		command = filter_input(command)
		vmrunstr = "vmrun -T ws -gu \"#{@vm_user}\" -gp \"#{@vm_pass} \" " +
				"runProgramInGuest \"#{@location}\" \"#{command}\""
		system_command(vmrunstr)
	end
	
	def copy_from(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} copyFileFromGuestToHost" +
				" \"#{@location}\" \"#{from}\" \"#{to}\"" 
		system_command(vmrunstr)
	end

	def copy_to(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} copyFileFromHostToGuest" +
				" \"#{@location}\" \"#{from}\" \"#{to}\""  
		system_command(vmrunstr)
	end

	def check_file_exists(file)
		file = filter_input(file)
		vmrunstr = "vmrun -T ws -gu {user} -gp #{@vm_pass} fileExistsInGuest " +
				"\"#{@location}\" \"#{file}\" "
		system_command(vmrunstr)
	end

	def create_directory(directory)
		directory = filter_input(directory)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} createDirectoryInGuest " +
				" \"#{@location}\" \"#{directory}\" "
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
