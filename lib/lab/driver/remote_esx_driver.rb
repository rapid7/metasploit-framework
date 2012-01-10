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
		@port = config['port']		
	end

	def start
		remote_system_command("vim-cmd vmsvc/power.on #{@vmid}")
	end

	def stop
		remote_system_command("vim-cmd vmsvc/power.off #{@vmid}")
	end

	def suspend
		remote_system_command("vim-cmd vmsvc/power.suspend #{@vmid}")
	end

	def pause
		remote_system_command("vim-cmd vmsvc/power.suspend #{@vmid}")
	end

	def resume
		remote_system_command("vim-cmd vmsvc/power.suspendResume #{@vmid}")
	end

	def reset
		remote_system_command("vim-cmd vmsvc/power.reset #{@vmid}")
	end

	def create_snapshot(snapshot)
		snapshot = filter_input(snapshot)
		
		remote_system_command("vim-cmd vmsvc/snapshot.create #{@vmid} #{snapshot} \'lab created snapshot\' 1 true")
	end

	def revert_snapshot(snapshot)

		snapshots = get_snapshots
		
		# Look through our snapshot list, choose the right one based on display_name		
		snapshots.each do |snapshot_obj|
		
			#puts "DEBUG: checking #{snapshot_obj}"
		
			if snapshot_obj[:display_name].downcase == snapshot.downcase
				snapshot_identifier = snapshot_obj[:name].join(" ")
				
				#puts "DEBUG: I would revert to #{snapshot_obj}"
				remote_system_command("vim-cmd vmsvc/snapshot.revert #{@vmid} 0 #{snapshot_identifier}")
				return true
			end
		end
	
		# If we got here, the snapshot didn't exist
		raise "Invalid Snapshot Name"
	end

	def delete_snapshot(snapshot, remove_children=false)
		snapshots = get_snapshots
		
		# Look through our snapshot list, choose the right one based on display_name		
		snapshots.each do |snapshot_obj|
		
			#puts "DEBUG: checking #{snapshot_obj}"
		
			if snapshot_obj[:display_name].downcase == snapshot.downcase
				snapshot_identifier = snapshot_obj[:name].join(" ")
				remote_system_command("vim-cmd vmsvc/snapshot.remove #{@vmid} #{remove_children} #{snapshot_identifier}")
				return true
			end
		end
	
		# If we got here, the snapshot didn't exist
		raise "Invalid Snapshot Name"
	end
	
	def delete_all_snapshots
		remote_system_command("vim-cmd vmsvc/snapshot.removeall #{@vmid}")
	end

	def check_file_exists(file)
		raise "Not Implemented"
	end

	def create_directory(directory)
		raise "Not Implemented"
	end

	def run_command(command, timeout=60)
		
		setup_session
		#puts "Using session #{@session}"
		
		# TODO: pass the timeout down
	
		if @session
			if @session.type == "shell"
				#puts "Running command via shell: #{command}"
				@session.shell_command_token(command, timeout)
			elsif @session.type == "meterpreter" 
				#puts "Running command via meterpreter: #{command}"
				@session.shell_command(command)
			end
		else
			raise "No session"
		end
	end

	def copy_to_guest(local,remote)
		setup_session
		if @session.type == "meterpreter"
			@session.run_cmd("upload #{local} #{remote}")
		else
			@driver.copy_to(local,remote)
		end
	end
	
	def copy_from_guest(local, remote)
		setup_session
		if @session.type == "meterpreter"
			@session.run_cmd("download #{local} #{remote}")
		else
			@driver.copy_from(local,remote)
		end
	end

	def cleanup
	end

	def running?
		power_status_string = `ssh #{@user}@#{@host} \"vim-cmd vmsvc/power.getstate #{@vmid}\"`
		return true if power_status_string =~ /Powered on/
	end 

private

	def create_framework
		return if @framework
		@framework	= Msf::Simple::Framework.create
	end

	# perform the setup only once
	def setup_session
		return if @session

		# require the framework (assumes this sits in lib/lab/modifiers)
		require 'msf/base'

		create_framework # TODO - this should use a single framework for all hosts, not one-per-host

		@session = nil
		@session_input	= Rex::Ui::Text::Input::Buffer.new
		@session_output	= Rex::Ui::Text::Output::Buffer.new
	
		if @os == "windows"
			exploit_name = 'windows/smb/psexec'

			# TODO - check for x86, choose the appropriate payload

			payload_name = 'windows/meterpreter/bind_tcp'
			options = {	
				"RHOST"		=> @hostname, 
				"SMBUser"	=> @vm_user, 
				"SMBPass"	=> @vm_pass}

			#puts "DEBUG: using options #{options}"

			# Initialize the exploit instance
			exploit = @framework.exploits.create(exploit_name)

			begin
				# Fire it off.
				@session = exploit.exploit_simple(
					'Payload'     	=> payload_name,
					'Options'     	=> options,
					'LocalInput'  	=> @session_input,
					'LocalOutput' 	=> @session_output)
				@session.load_stdapi
				
				#puts "DEBUG: Generated session: #{@session}"
				
			rescue  Exception => e 
					#puts "DEBUG: Unable to exploit"
					#puts e.to_s
			end
		else
			module_name = 'scanner/ssh/ssh_login'

			# TODO - check for x86, choose the appropriate payload
			
			payload_name = 'linux/x86/shell_bind_tcp'
			options = {	"RHOSTS"		=> @hostname, 
					"USERNAME" 		=> @vm_user, 
					"PASSWORD" 		=> @vm_pass, 
					"BLANK_PASSWORDS" 	=> false, 
					"USER_AS_PASS" 		=> false, 
					"VERBOSE" 		=> false}

			# Initialize the module instance
			aux = @framework.auxiliary.create(module_name)

			#puts "DEBUG: created module: #{aux}"

			begin 
				# Fire it off.
				aux.run_simple(
					'Payload'     => payload_name,
					'Options'     => options,
					'LocalInput'  => @session_input,
					'LocalOutput' => @session_output)

				@session = @framework.sessions.first.last
			rescue Exception => e 
				#puts "DEBUG: Unable to exploit"
				#puts e.to_s
			end
		end
	end

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
					current_num = 0
					current_tree = current_tree + 1 # new tree
					snapshots << { :name => [current_num, current_tree], :display_name => output_lines[count+1].split(":").last.strip }
				else
					current_num = current_num + 1 # new snapshot in current tree
					snapshots << { :name => [current_num, current_tree], :display_name => output_lines[count+1].split(":").last.strip }
				end
			end
			count = count+1
		end

	snapshots
	end

end

end 
end
