##
## $Id$
##
## This is the main lab controller.
##
##

$:.unshift(File.expand_path(File.dirname(__FILE__))) ## Msf Test libraries

require 'find'
require 'enumerator'
require 'vm'
require 'yaml'
require 'workstation_controller'
require 'workstation_vixr_controller'
require 'remote_workstation_controller'
require 'virtualbox_controller'
require 'dynagen_controller'
#require 'qemu_controller'
#require 'qemudo_controller'
#require 'amazon_controller'

module Lab
module Controllers
	class VmController 

		include Enumerable
		include Lab::Controllers::WorkstationController 	
		include Lab::Controllers::WorkstationVixrController 	
		include Lab::Controllers::RemoteWorkstationController 	
		include Lab::Controllers::VirtualBoxController 
		include Lab::Controllers::DynagenController 
		#include Lab::Controllers::QemuController 
		#include Lab::Controllers::QemudoController 
		#include Lab::Controllers::AmazonController 


		def initialize (labdef=nil)
			@vms = [] ## Start with an empty array of vms

			## labdef is a big array of hashes, use yaml to store
			labdef = [] unless labdef 
			
			## Create vm objects from the lab definition
			load_vms(labdef)
		end
		
		def clear!
			@vms = []
		end

		def [](x)
			find_by_vmid(x)
		end

		def find_by_vmid(vmid)
			@vms.each do |vm|
				if (vm.vmid.to_s == vmid.to_s)
					return vm
				end
			end
			return nil
		end

		def add_vm(vmid, type,location,credentials=nil,user=nil,host=nil)			
			@vms << Vm.new( {	'vmid' => vmid, 
						'driver' => type, 
						'location' => location, 
						'credentials' => credentials,
						'user' => user,
						'host' => host} )
		end

		def remove_by_vmid(vmid)
			@vms.delete(self.find_by_vmid(vmid))
		end	

		def from_file(file)
			labdef = YAML::load_file(file)
			load_vms(labdef)
		end

		def load_vms(vms)
			vms.each do |item|
				begin
					vm = Vm.new(item)
					@vms << vm unless includes_vmid? vm.vmid
				rescue Exception => e
					puts "Invalid VM definition"
					puts "Exception: #{e.to_s}"
				end 
			end
		end

		def to_file(file)
			File.open(file, 'w') { |f| @vms.each { |vm| f.puts vm.to_yaml } } 
		end

		def each &block
			@vms.each { |vm| yield vm }
		end

		def includes?(specified_vm)
			@vms.each { |vm| if (vm == specified_vm) then return true end  }
		end

		def includes_vmid?(vmid)
			@vms.each do |vm| 
				return true if (vm.vmid == vmid)
			end
			return false
		end

		def build_from_dir(type, dir, clear=false)
		
			if clear
				@vms = []
			end

			if type.downcase == "workstation"
				vm_list = ::Lab::Controllers::WorkstationController::dir_list(dir)
			elsif type.downcase == "remote_workstation"	
				vm_list = ::Lab::Controllers::RemoteWorkstationController::dir_list(dir)
			elsif type.downcase == "virtualbox"	
				vm_list = ::Lab::Controllers::VirtualBoxController::dir_list(dir)
			else
				raise TypeError, "Unsupported VM Type"
			end
			
			vm_list.each_index do |index|
				puts "Creating VM object for: " + vm_list[index]
				@vms << Vm.new( {'vmid' => index.to_s, 'driver' => type, 'location' => vm_list[index]} )
			end
		end

		def build_from_running(type=nil, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			case type.intern
				when :workstation
					vm_list = ::Lab::Controllers::WorkstationController::running_list
					
					vm_list.each do |item|
			
						## Name the VM
						index = @vms.count + 1
	
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => index.to_s,
									'driver' => type, 
									'location' => item, 
									'user' => user,
									'host' => host } )
					end
					
				when :remote_workstation
					vm_list = ::Lab::Controllers::RemoteWorkstationController::running_list(user, host)
					
					vm_list.each do |item|
			
						## Name the VM
						index = @vms.count + 1
	
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{index}",
									'driver' => type, 
									'location' => item, 
									'user' => user,
									'host' => host } )
					end
					
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::running_list
					
					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => type, 
									'location' => nil, 
									'user' => user,
									'host' => host } )
					end
						
				else
					raise TypeError, "Unsupported VM Type"
				end

		end	

		def build_from_config(type=nil, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			case type.intern
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::config_list
					
					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => type, 
									'location' => nil, 
									'user' => user,
									'host' => host } )
					end
						
				else
					raise TypeError, "Unsupported VM Type"
				end

		end	

		def running?(vmid)
			if includes_vmid?(vmid)
				return self.find_by_vmid(vmid).running?
			end
			return false 
		end
	end
end
end
