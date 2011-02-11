require 'vm_driver'

##
## $Id$
##
module Lab
module Drivers
	class VirtualBoxDriver < VmDriver

		attr_accessor :type
		attr_accessor :location

		def initialize(location)
			if !File.exist?(location)
				raise ArgumentError,"Couldn't find: " + location
			end

			@location = filter_input(location)
			@type = "vbox"
			@name = ""
			
			register

		end

		def register
			name_string = `VBoxManage registervm #{@location}`
			##TODO - parse out name / uuid
		end

		def unregister
			system_command("VBoxManage unregistervm #{@name}")
		end

		def start
			system_command("VBoxManage startvm #{@name}")
		end

		def stop
			system_command("VBoxManage controlvm#{@name} poweroff")
		end

		def suspend
			system_command("VBoxManage controlvm #{@name} pause")
		end

		def pause
			system_command("VBoxManage controlvm #{@name} pause")
		end

		def reset
			system_command("VBoxManage controlvm #{@name} reset")
		end

		def create_snapshot(name)
			system_command("VBoxManage snapshot #{@name} take " + name)
		end

		def revert_snapshot(name)
			system_command("VBoxManage snapshot #{@name} restore " + name)
		end

		def delete_snapshot(name)
			system_command("VBoxManage snapshot #{@name} delete " + name )
		end

		def run_command(command, arguments, user, pass)
			command = "VBoxManage execute #{@name} #{command} --username #{username}
					 --password #{password} --arguments \"#{arguments}\""
			system_command(command)
		end
	
		def copy_from(user, pass, from, to)
			command = "VBoxManage " ##TODO
			system_command(command)
		end

		def copy_to(user, pass, from, to)
			command = "VBoxManage "  ##TODO 
			system_command(command)
		end

		def check_file_exists(user, pass, file)
			command = "VBoxManage " ##TODO
			system_command(command)
		end

		def create_directory(user, pass, directory)
			command = "VBoxManage " ##TODO
			system_command(command)
		end

		def cleanup
			self.unregister
		end

		def running?
			## Get running Vms
			running = `VBoxManage list runningvms`
			running_array = running.split("\n")

			## Skip the first 4 lines of output
			4.times { running_array.shift } 

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
