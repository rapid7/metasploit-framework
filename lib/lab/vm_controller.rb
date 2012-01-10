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
		include Lab::Controllers::VirtualBoxController 
		include Lab::Controllers::FogController
		include Lab::Controllers::DynagenController 
		include Lab::Controllers::RemoteEsxController
		include Lab::Controllers::RemoteWorkstationController 	
		#include Lab::Controllers::QemuController 
		#include Lab::Controllers::QemudoController 
		def initialize (labdef=nil)
			
			# Start with an empty array of vm objects
			@vms = [] 

			# labdef is a just a big array of hashes
			load_vms(labdef) if labdef
		end
		
		def clear!
			@vms = []
		end

		def [](x)
			# Support indexing by both names and number
			if x.class == String
				find_by_hostname(x)
			else
				return @vms[x]
			end
		end

		def find_by_hostname(vmid)
			@vms.each do |vm|
				if (vm.hostname.to_s.downcase == vmid.to_s.downcase)
					return vm
				end
			end
		return nil
		end

		def find_by_tag(tag_name)
			tagged_vms = []
		 	@vms.each { |vm| tagged_vms << vm if vm.tagged?(tag_name) }
		return tagged_vms
		end

		def add_vm(vmid, location=nil, os=nil, tools=nil, credentials=nil, user=nil, host=nil)			
			@vms << Vm.new( {	'vmid' => vmid, 
						'driver' => type, 
						'location' => location, 
						'credentials' => credentials,
						'user' => user,
						'host' => host} )
		end

		def remove_by_vmid(vmid)
			@vms.delete(self.find_by_hostname(vmid))
		end	

		def from_file(file)
			load_vms(YAML::load_file(file))
		end

		def load_vms(vms)
			vms.each do |item|
				vm = Vm.new(item)
				@vms << vm unless includes_vmid? vm.vmid
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
		false
		end

		def includes_hostname?(hostname)
			@vms.each do |vm|
				return true if (vm.hostname == hostname)
			end
		false
		end


		def build_from_dir(driver_type, dir, clear=false)
		
			if clear
				@vms = []
			end

			if driver_type.downcase == "workstation"
				vm_list = ::Lab::Controllers::WorkstationController::dir_list(dir)
			elsif driver_type.downcase == "virtualbox"	
				vm_list = ::Lab::Controllers::VirtualBoxController::dir_list(dir)
			elsif driver_type.downcase == "fog"
				vm_list = ::Lab::Controllers::FogController::dir_list(dir)
			elsif driver_type.downcase == "Dynagen"	
				vm_list = ::Lab::Controllers::DynagenController::dir_list(dir)
			elsif driver_type.downcase == "remote_workstation"	
				vm_list = ::Lab::Controllers::RemoteWorkstationController::dir_list(dir)
			elsif driver_type.downcase == "remote_esx"
				vm_list =::Lab::Controllers::RemoteEsxController::dir_list(dir)
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
				when :virtualbox
					vm_list = ::Lab::Controllers::VirtualBoxController::running_list
					vm_list.each do |item|
						## Add it to the vm list
						@vms << Vm.new( {	'vmid' => "#{item}",
									'driver' => driver_type,
									'location' => nil })
					end
				when :fog
					raise "Unsupported" # TODO - figure out a way to allow this
				when :dynagen
					raise "Unsupported"
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
				return self.find_by_hostname(vmid).running?
			end
			return false
		end
	end
end
end
