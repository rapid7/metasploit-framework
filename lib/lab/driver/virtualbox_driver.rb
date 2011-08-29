require 'vm_driver'
require 'nokogiri'

##
## $Id$
##
module Lab
module Drivers
	class VirtualBoxDriver < VmDriver

		attr_accessor :location

		def initialize(config)

			super(config)

			## Check to see if we already know this vm, if not, go on location
			vmid_list = ::Lab::Controllers::VirtualBoxController::config_list
			unless vmid_list.include? @vmid
				raise "Error, no such vm: #{@vmid}" unless @location
				
				if !File.exist?(@location)
					raise ArgumentError,"Error, no vm at: #{@location}"
				end
				
				# Registering @location
				@vmid = register_and_return_vmid
			end
			
			vmInfo = `VBoxManage showvminfo \"#{@vmid}\" --machinereadable`
			@location = vmInfo.scan(/CfgFile=\"(.*?)\"/).flatten[0].to_s

			if !File.exist?(@location)
				raise ArgumentError,"Couldn't find: " + @location
			end

		end

		def register_and_return_vmid
			
			xml = Nokogiri::XML(File.new(@location))
			vmid = xml.root.xpath("//Machine[@name]")
			
			## only register if we don't already know the vmid
			if !::Lab::Controllers::VirtualBoxController::config_list.include? vmid
				system_command("VBoxManage registervm \"#{@location}\"")
			end
			
			return vmid
			
		end

		def unregister
			system_command("VBoxManage unregistervm \"#{@vmid}\"")
		end

		def start
			system_command("VBoxManage startvm \"#{@vmid}\"")
		end

		def stop
			system_command("VBoxManage controlvm \"#{@vmid}\" poweroff")
		end

		def suspend
			system_command("VBoxManage controlvm \"#{@vmid}\" savestate")
		end

		def pause
			system_command("VBoxManage controlvm \"#{@vmid}\" pause")
		end

		def reset
			system_command("VBoxManage controlvm \"#{@vmid}\" reset")
		end

		def create_snapshot(snapshot)
			snapshot = filter_input(snapshot)
			system_command("VBoxManage snapshot \"#{@vmid}\" take #{snapshot}")
		end

		def revert_snapshot(snapshot)
			snapshot = filter_input(snapshot)
			system_command("VBoxManage snapshot \"#{@vmid}\" restore #{snapshot}")
		end

		def delete_snapshot(snapshot)
			snapshot = filter_input(snapshot)
			system_command("VBoxManage snapshot \"#{@vmid}\" delete  #{snapshot}")
		end

		def run_command(command, arguments=nil)
			command = filter_input(command)
			arguments = filter_input(arguments)

			command = "VBoxManage guestcontrol exec \"#{@vmid}\" \"#{command}\" --username \"#{@vm_user}\"" +
					 " --password \"#{@vm_pass}\" --arguments \"#{arguments}\""
			system_command(command)
		end
	
		def copy_from(from, to)
			from = filter_input(from)
			to = filter_input(to)

			raise "Not supported by Virtual Box"
		end

		def copy_to(from, to)
			from = filter_input(from)
			to = filter_input(to)
			
			command = "VBoxManage guestcontrol copyto \"#{@vmid}\" \"#{from}\"  \"#{to}\" " +
					 "--username \"#{@vm_user}\" --password \"#{@vm_pass}\""
			system_command(command)
		end

		def check_file_exists(file)
			file = filter_input(file)

			raise "Not supported by Virtual Box"
		end

		def create_directory(directory)
			directory = filter_input(directory)

			command = "VBoxManage guestcontrol createdir \"#{@vmid}\" \"#{directory}\" " + 
					 "--username \"#{@vm_user}\" --password \"#{@vm_pass}\""
			system_command(command)
		end

		def cleanup

		end

		def running?
			## Get running Vms
			::Lab::Controllers::VirtualBoxController::running_list.include? @vmid
		end
		
	end
end
end
