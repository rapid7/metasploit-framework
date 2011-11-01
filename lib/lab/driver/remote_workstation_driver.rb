require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers

class RemoteWorkstationDriver < VmDriver

	attr_accessor :location # among other things

	def initialize(config)

		unless config['user'] then raise ArgumentError, "Must provide a username" end
		unless config['host'] then raise ArgumentError, "Must provide a hostname" end

		super(config)

		@user = filter_command(config['user'])
		@host = filter_command(config['host'])
	end

	def start
		remote_system_command("vmrun -T ws start \'#{@location}\' nogui")
	end

	def stop
		remote_system_command("vmrun -T ws stop \'#{@location}\' nogui")
	end

	def suspend
		remote_system_command("vmrun -T ws suspend \'#{@location}\' nogui")
	end

	def pause
		remote_system_command("vmrun -T ws pause \'#{@location}\' nogui")
	end

	def reset
		remote_system_command("vmrun -T ws reset \'#{@location}\' nogui")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		remote_system_command("vmrun -T ws snapshot \'#{@location}\' #{snapshot} nogui")
	end

	def revert_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		remote_system_command("vmrun -T ws revertToSnapshot \'#{@location}\' #{snapshot} nogui")
	end

	def delete_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		remote_system_command("vmrun -T ws deleteSnapshot \'#{@location}\' #{snapshot} nogui\"" )
	end
	
	def run_command(command)
		# generate local & remote script paths
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
			# copy it to the vm host - this is because we're a remote driver
			remote_copy_command = "scp #{local_tempfile_path} #{@user}@#{@host}:#{local_tempfile_path}"
			system_command(remote_copy_command)

			# we have it on the vm host, copy it to the vm guest
			vmrunstr = "ssh #{@user}@#{@host} \"vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromHostToGuest \'#{@location}\' \'#{local_tempfile_path}\' " +
					"\'#{remote_tempfile_path}\' nogui\""
			system_command(vmrunstr)

			# now run it on the guest
			vmrunstr = "ssh #{@user}@#{@host} \"vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " + 
					"runProgramInGuest \'#{@location}\' -noWait -activeWindow \'#{remote_run_command}\'\""
			system_command(vmrunstr)

			## CLEANUP
			# delete it on the guest
			vmrunstr = "ssh #{@user}@#{@host} \"vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " + 
					"deleteFileInGuest \'#{@location}\' \'#{remote_tempfile_path}\'\""
			system_command(vmrunstr)

			# and delete it on the vm host
			vmhost_delete_command = "ssh #{@user}@#{@host} rm #{local_tempfile_path}"
			system_command(vmhost_delete_command)

			# delete it locally
			local_delete_command = "rm #{local_tempfile_path}"
			system_command(local_delete_command)
		else
			# since we can't copy easily w/o tools, let's just run it directly :/
			if @os == "linux"
				scp_to(local_tempfile_path, remote_tempfile_path)
				ssh_exec(remote_run_command)
				ssh_exec("rm #{remote_tempfile_path}")
			else
				raise "Not Implemented - Install VmWare Tools"
			end	
		end
	end
	
	def copy_from(from, to)
		from = filter_input(from)
		to = filter_input(to)
		
		# copy it to the vm host - this is because we're a remote driver
		remote_copy_command = "scp #{from} #{@user}@#{@host}:#{from}"
		system_command(remote_copy_command)

		if @tools 
					
			remote_system_command("ssh #{@user}@#{@host} \"vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromGuestToHost \'#{@location}\' \'#{from}\' \'#{to}\' nogui")
		else
			scp_to(from,to)
		end
	end

	def copy_to(from, to)
	
		from = filter_input(from)
		to = filter_input(to)
		
		# copy it to the vm host - this is because we're a remote driver
		remote_copy_command = "scp #{from} #{@user}@#{@host}:#{from}"
		system_command(remote_copy_command)
		
		if @tools
			remote_system_command("vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"copyFileFromHostToGuest \'#{@location}\' \'#{from}\' \'#{to}\' nogui")
		else
			scp_to(from,to)
		end
	end

	def check_file_exists(file)
		
		if @tools
			file = filter_input(file)
			remote_system_command("vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"fileExistsInGuest \'#{@location}\' \'{file}\' nogui")
		else
			raise "Not Implemented - Install VmWare Tools"
		end
	end

	def create_directory(directory)
		directory = filter_input(directory)
	
		if @tools
			emote_system_command("ssh #{@user}@#{@host} vmrun -T ws -gu #{@vm_user} -gp #{@vm_pass} " +
					"createDirectoryInGuest \'#{@location}\' \'#{directory}\' nogui")
			system_command(vmrunstr)
		else
			raise "Not Implemented - Install VmWare Tools"
		end
	end

	def cleanup

	end

	def running?
		## Get running VMs
		running = `ssh #{@user}@#{@host} \"vmrun list nogui\"`
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
