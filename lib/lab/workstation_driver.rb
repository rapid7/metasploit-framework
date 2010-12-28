require 'vm_driver'

##
## $Id$
##

class WorkstationDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(location)
		if !File.exist?(location)
			raise ArgumentError,"Couldn't find: " + location
		end

		@location = location
		@type = "Workstation"
	end

	def start
		system_command("vmrun -T ws start " + "\"" + @location + "\"")
	end

	def stop
		system_command("vmrun -T ws stop " + "\"" + @location + "\"")
	end

	def suspend
		system_command("vmrun -T ws suspend " + "\"" + @location + "\"")
	end

	def pause
		system_command("vmrun -T ws pause " + "\"" + @location + "\"")
	end

	def reset
		system_command("vmrun -T ws reset " + "\"" + @location + "\"")
	end

	def create(snapshot)
		system_command("vmrun -T ws snapshot " + "\"" + @location + "\" " + snapshot)
	end

	def revert(snapshot)
		system_command("vmrun -T ws revertToSnapshot " + "\"" + @location + "\" " + snapshot)
	end

	def delete_snapshot(snapshot)
		system_command("vmrun -T ws deleteSnapshot " + "\"" + @location + "\" " + snapshot )
	end

	def run_command(command, user, pass)
		vmrunstr = "vmrun -T ws -gu \"" + user + "\" -gp \"" + pass + "\" runProgramInGuest \"" + 
				@location + "\" " + "\"" + command + "\" -noWait -activeWindow"

		system_command(vmrunstr)
	end
	
	def copy_from(user, pass, from, to)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromGuestToHost \"" +
				@location + "\" \"" + from + "\" \"" + to + "\"" 
		system_command(vmrunstr)
	end

	def copy_to(user, pass, from, to)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromHostToGuest \"" + 
				@location + "\" \"" + from + "\" \"" + to + "\""  
		system_command(vmrunstr)
	end

	def check_file_exists(user, pass, file)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " fileExistsInGuest \"" +
				@location + "\" \"" + file + "\" "
		system_command(vmrunstr)
	end

	def create_directory(user, pass, directory)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " createDirectoryInGuest \"" + 
				@location + "\" \"" + directory + "\" "
		system_command(vmrunstr)
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
