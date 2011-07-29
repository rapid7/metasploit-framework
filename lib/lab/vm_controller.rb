##
## $Id$
##
## This is the main lab controller. Require this controller to get all 
## lab functionality. 
##
##

$:.unshift(File.expand_path(File.dirname(__FILE__)))
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'driver')))
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'controller')))
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'modifier')))

require 'find'
require 'yaml'
require 'enumerator'
require 'fileutils'

require 'vm'
require 'controllers'
require 'drivers'
require 'modifiers'

module Lab
module Controllers
	class VmController 

		include Enumerable
		include Lab::Controllers::WorkstationController 	
		include Lab::Controllers::WorkstationVixrController 	
		include Lab::Controllers::RemoteWorkstationController 	
		include Lab::Controllers::VirtualBoxController 
		include Lab::Controllers::DynagenController 
		include Lab::Controllers::RemoteEsxController
		#include Lab::Controllers::QemuController 
		#include Lab::Controllers::QemudoController 
		#include Lab::Controllers::AmazonController
		#include Lab::Controllers::FogController


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
					# TODO -  this needs to go into a logfile and be raised up to an interface.
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

		def build_from_dir(driver_type, dir, clear=false)
		
			if clear
				@vms = []
			end

			if driver_type.downcase == "workstation"
				vm_list = ::Lab::Controllers::WorkstationController::dir_list(dir)
			elsif driver_type.downcase == "workstation_vixr"	
				vm_list = ::Lab::Controllers::WorkstationVixrController::dir_list(dir)
			elsif driver_type.downcase == "remote_workstation"	
				vm_list = ::Lab::Controllers::RemoteWorkstationController::dir_list(dir)
			elsif driver_type.downcase == "virtualbox"	
				vm_list = ::Lab::Controllers::VirtualBoxController::dir_list(dir)
			elsif driver_type.downcase == "remote_esx"
				vm_list =::Lab::Controllers::RemoteEsxController::dir_list(dir)
			#elsif driver_type.downcase == "esxi_vixr"
			#	vm_list =::Lab::Controllers::EsxiVixrController::dir_list(dir)
			#elsif driver_type.downcase == "fog"
			#	vm_list = ::Lab::Controllers::FogController::dir_list(dir)
			else
				raise TypeError, "Unsupported VM Type"
			end
			
			vm_list.each_index do |index|
				@vms << Vm.new( {'vmid' => "vm_#{index}", 'driver' => driver_type, 'location' => vm_list[index]} )
			end
		end

		def build_from_running(driver_type=nil, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			case driver_type.intern
				when :workstation
					vm_list = ::Lab::Controllers::WorkstationController::running_list
					
					vm_list.each do |item|
			
						## Name the VM
						index = @vms.count + 1
	
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "vm_#{index}",
									'driver' => driver_type, 
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
						@vms << Vm.new( {	'vmid' => "vm_#{index}",
									'driver' => driver_type, 
									'location' => item, 
									'user' => user,
									'host' => host } )
					end
					
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::running_list
					
					# TODO - why are user and host specified here?

					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => driver_type,
									'location' => nil, # this will be filled in by the driver
									'user' => user,
									'host' => host } )
					end

				when :remote_esx
					vm_list = ::Lab::Controllers::RemoteEsxController::running_list(user,host)
					
					vm_list.each do |item|
						@vms << Vm.new( {	'vmid' => "#{item[:id]}",
									'name' => "#{item[:name]}",
									'driver' => driver_type, 
									'user' => user,
									'host' => host } )
					end
						
				else
					raise TypeError, "Unsupported VM Type"
				end

		end	

		def build_from_config(driver_type=nil, user=nil, host=nil, clear=false)
		
			if clear
				@vms = []
			end

			case driver_type.intern
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::config_list
					
					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => driver_type, 
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
