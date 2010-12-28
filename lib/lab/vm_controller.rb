##
## $Id$
##
## This is the main lab controller which will call out to other controller
## libraries. Requiring this file and specifying the type of VM at initialization
## will allow you to start/stop/snapshot/revert & run commands on VMs
##
## $Revision$
##

$:.unshift(File.expand_path(File.dirname(__FILE__))) ## Msf Test libraries

require 'find'
require 'enumerator'
require 'vm'
require 'yaml'

#
# ~Higher-level lab methods which are generic to the types of things we want to do with a lab of machines
#  Note that any generic vm functionality should be pushed down into the controller class. 

class VmController 

	include Enumerable

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
			puts "Lab item: " + item.inspect
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

#	def includes?(vm)
#		@vms.each { |vm| if (vm.vmid.to_ == vmid.to_s) then return true end  }
#	end

	def includes_vmid?(vmid)
		@vms.each { |vm| if (vm.vmid.to_s == vmid.to_s) then return true end  }
	end

	def running?(vmid)
		if exists?(vmid)
			return self.find_by_vmid(vmid).running?
		end
		return false 
	end

	## Might want to mix this (workstation) functionality in?
	def build_from_running_workstation(clear=false)

		if clear
			@vms = []
		end
		
		vm_list = `vmrun list`.split("\n")
		vm_list.shift
		vm_list.each do |vmx|
			index = @vms.count + 1 ## give us a vmid!
			@vms << Vm.new( {"vmid" => index, "driver" => "workstation", 
					"location" => vmx})
		end
	end

	def build_from_dir_workstation(basepath=nil, clear=false)
	
		if clear
			@vms = []
		end

		vm_list = Find.find(basepath).select { |f| f =~ /\.vmx$/ }
		vm_list.each do |vmx|
			index = @vms.count + 1 ## give us a vmid!
			@vms << Vm.new( {"vmid" => index, "driver" => "workstation",
					"location" => vmx})
		end
	end
end
