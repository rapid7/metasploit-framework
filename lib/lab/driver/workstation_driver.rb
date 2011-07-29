require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers

class WorkstationDriver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(vmid, location, os=nil, tools=false, credentials=nil)
		@vmid = filter_command(vmid)
		@location = filter_command(location)

		if !File.exist?(@location)
			raise ArgumentError,"Couldn't find: " + @location
		end

		@credentials = credentials
		@tools = tools	# not used in command lines, no filter
		@os = os	# not used in command lines, no filter

		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user']) || "\'\'"
			@vm_pass = filter_input(@credentials[0]['pass']) || "\'\'"
		end
	end

	def start
		system_command("vmrun -T ws start " + "\'#{@location}\' nogui")
	end

	def stop
		system_command("vmrun -T ws stop " + "\'#{@location}\' nogui")
	end

	def suspend
		system_command("vmrun -T ws suspend " + "\'#{@location}\' nogui")
	end

	def pause
		system_command("vmrun -T ws pause " + "\'#{@location}\' nogui")
	end

	def reset
		system_command("vmrun -T ws reset " + "\'#{@location}\' nogui")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("vmrun -T ws snapshot " + "\'#{@location}\' \'#{snapshot}\' nogui")
	end

	def revert_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("vmrun -T ws revertToSnapshot " + "\'#{@location}\' \'#{snapshot}\' nogui")
	end

	def delete_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		system_command("vmrun -T ws deleteSnapshot " + "\'#{@location}\' \'#{snapshot}\' nogui" )
	end

	def run_command(command)

		script_rand_name = rand(10000)

		if @os == "windows"
			local_tempfile_path = "/tmp/lab_script_#{script_rand_name}.bat"
			remote_tempfile_path = "C:\\\\lab_script_#{script_rand_name}.bat"
			remote_run_command = remote_tempfile_path
		else
			local_tempfile_path = "/tmp/lab_script_#{script_rand_name}.sh"
			remote_tempfile_path = "/tmp/lab_script_#{script_rand_name}.sh"
			remote_run_command = "/bin/sh #{remote_tempfile_path}"
		end

		# write out our script locally
		File.open(local_tempfile_path, 'w') {|f| f.write(command) }

		# we really can't filter command, so we're gonna stick it in a script
		if @tools
			# copy our local tempfile to the guest
			vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromHostToGuest \'#{@location}\' \'#{local_tempfile_path}\'" +
					" \'#{remote_tempfile_path}\' nogui"
			system_command(vmrunstr)

			# now run it on the guest
			vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " + 
					"runProgramInGuest \'#{@location}\' -noWait -activeWindow \'#{remote_run_command}\'"
			system_command(vmrunstr)

			## CLEANUP
			# delete it on the guest
			vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " + 
					"deleteFileInGuest \'#{@location}\' \'#{remote_tempfile_path}\'"
			system_command(vmrunstr)

			# delete it locally
			local_delete_command = "rm #{local_tempfile_path}"
			system_command(local_delete_command)
		else
			# since we can't copy easily w/o tools, let's just run it directly :/
			if @os == "linux"
				
				output_file = "/tmp/lab_command_output_#{rand(1000000)}"
				
				scp_to(local_tempfile_path, remote_tempfile_path)
				ssh_exec(remote_run_command + "> #{output_file}")
				scp_from(output_file, output_file)
				
				ssh_exec("rm #{output_file}")
				ssh_exec("rm #{remote_tempfile_path}")
				
				# Ghettohack!
				string = File.open(output_file,"r").read
				`rm #{output_file}`
				
			else
				raise "zomgwtfbbqnotools"
			end	
		end
	return string
	end
	
	def copy_from(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vmrunstr = "vmrun -T ws -gu \'#{@vm_user}\' -gp \'#{@vm_pass}\' copyFileFromGuestToHost " +
				"\'#{@location}\' \'#{from}\' \'#{to}\'" 
		system_command(vmrunstr)
	end

	def copy_to(from, to)
		from = filter_input(from)
		to = filter_input(to)
		vmrunstr = "vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} copyFileFromHostToGuest " +
				"\'#{@location}\' \'#{from}\' \'#{to}\'"  
		system_command(vmrunstr)
	end

	def check_file_exists(file)
		file = filter_input(file)
		vmrunstr = "vmrun -T ws -gu \'#{@vm_user}\' -gp \'#{@vm_pass}\' fileExistsInGuest " +
				"\'#{@location}\' \'#{file}\' "
		system_command(vmrunstr)
	end

	def create_directory(directory)
		directory = filter_input(directory)
		vmrunstr = "vmrun -T ws -gu \'#{@vm_user}\' -gp \'#{@vm_pass}\' createDirectoryInGuest " +
				" \'#{@location}\' \'#{directory}\' "
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
