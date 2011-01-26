##
## $Id$
##
## This is the main lab controller. Require this file to create a lab of vms
##
##

$:.unshift(File.expand_path(File.dirname(__FILE__))) ## Msf Test libraries

require 'find'
require 'enumerator'
require 'vm'
require 'yaml'
require 'workstation_controller'
require 'remote_workstation_controller'
#require 'amazon_controller'
#require 'virtualbox_controller'
#require 'dynagen_controller'

module Lab
module Controllers
	class VmController 

		include Enumerable
		include Lab::Controllers::WorkstationController 		## gives access to workstation-specific controller methods
		include Lab::Controllers::RemoteWorkstationController 	## gives access to workstation-specific controller methods
		#include Lab::AmazonController 		## gives access to amazon-specific controller methods
		#include Lab::VirtualBoxController 	## gives access to virtualbox-specific controller methods
		#include Lab::DynagenController 		## gives access to dynagen-specific controller methods


		def initialize (labdef = nil)
		
			@vms = [] ## Start with an empty array of vms

			## labdef is a big array of hashes (vms) - generally loaded from yaml
			if !labdef 
				labdef = [] ## Just use a blank lab to start
			else
				labdef = labdef
			end

			## Create vm objects from the lab definition
			labdef.each do |item|
				begin
					@vms << Vm.new(item)
				rescue Exception => e
					puts e.to_s
				end  
			end

		end
	
		def clear!
			@vms = []
		end

		def find_by_vmid(vmid)
			@vms.each do |vm|

				if (vm.vmid.to_s == vmid.to_s)
					return vm
				end
			end
			return nil
		end

		def from_file(file)
			labdef = YAML::load_file(file)

			labdef.each do |item|
				#puts "Lab item: " + item.inspect
				@vms << Vm.new(item)
			end
		end

		def to_file(file)
			File.open(file, 'w') do |f|
				@vms.each { |vm| f.puts vm.to_yaml }
			end
		end

		def each
			@vms.each { |vm| yield vm }
		end

		def includes?(specified_vm)
			@vms.each { |vm| if (vm == specified_vm) then return true end  }
		end

		def includes_vmid?(vmid)
			@vms.each { |vm| if (vm.vmid.to_s == vmid.to_s) then return true end  }
		end

		def build_from_dir(dir, type, clear=false)
		
			if clear
				@vms = []
			end

			if type.downcase == "workstation"
				vm_list = WorkstationController::workstation_dir_list(dir)
			elsif type.downcase == "remote_workstation"	
				vm_list = RemoteWorkstationController::workstation_dir_list(dir)
			else
				raise TypeError, "Unsupported VM Type"
			end
			
			vm_list.each do |item|
				index = @vms.count + 1
				@vms << Vm.new( {"vmid" => index, "driver" => type, "location" => item} )
			end
		end

		def build_from_running(type, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			if type.downcase == "workstation"
				vm_list = WorkstationController::workstation_running_list
			elsif type.downcase == "remote_workstation"
				vm_list = RemoteWorkstationController::workstation_running_list(user, host)
			else
				raise TypeError, "Unsupported VM Type"
			end
			
			vm_list.each do |item|
				index = @vms.count + 1
				@vms << Vm.new( {"vmid" => index, "driver" => type, "location" => item} )
			end
		end

		def add_vm(vmid, type,location,credentials=nil,user=nil,host=nil)			
			@vms << Vm.new( {	"vmid" => vmid, 
						"driver" => type, 
						"location" => location, 
						"credentials" => credentials,
						"user" => user,
						"host" => host
						} )
		end

		def remove_by_vmid(vmid)
			@vms.delete(self.find_by_vmid(vmid))
		end		

		def running?(vmid)
			if exists?(vmid)
				return self.find_by_vmid(vmid).running?
			end
			return false 
		end
	end
end
end
