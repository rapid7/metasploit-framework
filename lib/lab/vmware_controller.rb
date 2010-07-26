#$Id$
#
# Lower level methods which are ~generic to vm software
#

## VmwareController Wraps vmrun and gives us basic vm functionality 
class VmwareController

	def initialize
	end

	def start(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws start " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def stop(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws stop " + "\"" + vmx + "\"")
		else
			raise ArgumentError,"Couldn't find:  " + vmx, caller
		end
	end

	def suspend(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws suspend " + "\"" + vmx + "\"")
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def pause(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws pause " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def reset(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws reset " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def run_command(vmx, command, user, pass, displayParameter=false)
		if File.exist?(vmx)
			
			vmrunstr = "vmrun -T ws -gu \"" + user + "\" -gp \"" + pass + "\" runProgramInGuest \"" + vmx + "\" " + "\"" + command + "\" -noWait -activeWindow"
	
			if displayParameter
				vmrunstr = vmrunstr + " -display :0"
			end

			system_command(vmrunstr)
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end
	
	def run_ssh_command(hostname, command, user)
		ssh_command = "ssh " + user + "@" + hostname + " " + command
		system_command(ssh_command)
	end

	def copy_file_from(vmx, user, pass, guestpath, hostpath)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromGuestToHost \"" + vmx + "\" \"" + guestpath + "\" \"" + hostpath + "\"" 
		system_command(vmrunstr)
	end
	
	def scp_copy_file_from(hostname, user, guestpath, hostpath)
		vmrunstr = "scp -r \"" + user + "@" + hostname + ":" + guestpath + "\" \"" + hostpath + "\"" ## TODO - setup keys  
		system_command(vmrunstr)
	end

	def copy_file_to(vmx, user, pass, hostpath, guestpath)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromHostToGuest \"" + vmx + "\" \"" + hostpath + "\" \"" + guestpath + "\""  
		system_command(vmrunstr)
	end

	def scp_copy_file_to(hostname, user, hostpath, guestpath)
		vmrunstr = "scp -r \"" + hostpath + "\" \"" + user + "@" + hostname + ":" + guestpath + "\"" ## TODO - setup keys  
		system_command(vmrunstr)
	end

	def check_file_exists(vmx, user, pass, file)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " fileExistsInGuest \"" + vmx + "\" \"" + file + "\" "
		system_command(vmrunstr)
	end

	def create_directory_in_guest(vmx, user, pass, directory)
		vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " createDirectoryInGuest \"" + vmx + "\" \"" + directory + "\" "
		system_command(vmrunstr)
	end

	def create_snapshot(vmx, snapshot)
		if File.exist?(vmx)
			system_command("vmrun -T ws snapshot " + "\"" + vmx + "\" " + snapshot)
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def revert_snapshot(vmx, snapshot)
		if File.exist?(vmx)
			system_command("vmrun -T ws revertToSnapshot " + "\"" + vmx + "\" " + snapshot)
		else
			raise "Couldn't find: " + vmx, caller
		end
	end

	def delete_snapshot(vmx, snapshot)
		if File.exist?(vmx)
			system_command("vmrun -T ws deleteSnapshot " + "\"" + vmx + "\" " + snapshot )
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def get_running
		output = `vmrun list` ##hackity hack=begin
		return output
	end

	def running?(vmx)
		output = self.get_running
		output.each_line do |line| 
			if line.strip == vmx.strip
				return true
			end
		end

		return false
	end

	private

	def system_command(command)
		puts "DEBUG: " + command
		system(command)
	end

end
