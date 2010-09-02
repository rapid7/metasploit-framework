#
# $Id$
# $Revision$
#

#$:.unshift(File.dirname(__FILE__))

require 'find'
require 'vmware_controller'

## Not implemented yet!
#require 'vbox_controller'
#require 'qemu_controller'
#require 'ec2_controller'

#
# ~Higher-level lab methods which are generic to the types of things we want to do with a lab of machines
#  Note that any generic vm functionality should be pushed down into the controller class. 

class LabController 

	attr_accessor :labdef
	attr_accessor :controller

	def initialize (labdef = nil, labtype="vmware")
		
		if !labdef 
			## Just use a blank lab to start
			@labdef = {}
		else
			@labdef = labdef
		end		

		### AHH, traverse again, looking for nils, cuz ruby is teh fail - TODO -  value?		
		@labdef.each do |key,value|
			@labdef[key].each do |subkey,subvalue|
				if !subvalue
					@labdef[key][subkey] = ""
				end
			end
		end
		
				
		## set up the controller. note that this is likely to change in the future (to provide for additional vm libs)
		if labtype == "vmware"
			@controller = VmwareController.new
			@file_extension = "vmx"

##	
##	Not implemented yet!
##
##		elsif labtype == "qemu"
##			@controller = QemuController.new
##			@file_extension = "img"
##		elsif labtype == "ec2"
##			@controller = Ec2Controller.new

		else
			raise "Invalid Lab Controller"
		end
	end

	def contains?(vmid)
		if get_full_path(vmid)
		 	true
	 	end
	end 
	
	def build_lab_from_running()
		vm_array = self.list_lab_running.split("\n") ## this should probably return an array
		vm_array.shift
		hlp_stuff_array_into_lab(vm_array)
	end

	def build_lab_from_files(basepath=nil)
		vm_array = Find.find(basepath).select { |f| 
			f =~ /\.#{@file_extension}$/ #&& File.executable?(f)
		}

		hlp_stuff_array_into_lab(vm_array)
	end

	def hlp_stuff_array_into_lab(arr)
		return false unless arr.kind_of? Array
	
		arr.each_with_index {|v,i|
			## give us a vmid!
			index = @labdef.count + 1

			## eliminate dooops
			fresh = true
			@labdef.each { |vmid, definition| fresh = false if labdef[vmid]['file'] == 'v' }
			
			if fresh
				@labdef[index.to_s] = {'file' => v }
			end
			#end
		}
		return @labdef
	end

	def run_command_on_lab_vm(vmid,command,arguments=nil)
		if @labdef[vmid]["tools"]
			@controller.run_command(get_full_path(vmid), command, @labdef[vmid]["user"],@labdef[vmid]["pass"])
		else
			if @labdef[vmid]["os"] == "linux"
				@controller.run_ssh_command(@labdef[vmid]["hostname"], command , @labdef[vmid]["user"])
			else
				raise "OS Not Supported"
			end
		end
	end

	def run_browser_on_lab_vm(vmid,uri)
		if @labdef[vmid]["os"] == "linux"
			command = "firefox " + uri
		elsif @labdef[vmid]['os'] == "windows"
			command = "C:\\Progra~1\\intern~1\\iexplore.exe " + uri
		else
			raise "Don't know how to browse to '" + uri + "'."
		end
		run_command_on_lab_vm(vmid,command)
	end

	def start_lab_vm(vmid)
		if running?(vmid)
			self.list_lab_running
		else
			@controller.start(get_full_path(vmid)) 
		end
	end
	
	def reset_lab_vm(vmid)
		@controller.reset(get_full_path(vmid))
	end

	def pause_lab_vm(vmid)
		if !running?(vmid)
			self.list_lab_running
		else
			@controller.pause(get_full_path(vmid)) 
		end
	end

	def suspend_lab_vm(vmid)
		if !running?(vmid)
			self.list_lab_running
		else
				@controller.suspend(get_full_path(vmid))
		end
	end

	def snapshot_lab_vm(vmid, snapshot)
		if !running?(vmid)
			self.list_lab_running
		else
			@controller.create_snapshot(get_full_path(vmid),snapshot)
		end
	end

	def revert_lab_vm(vmid, snapshot, run=true)
		if !running?(vmid)
			self.list_lab_running
		else
			@controller.revert_snapshot(get_full_path(vmid),snapshot)

			## If you revert w/ vmrun, you need to restart
			if run 
				sleep 5
				@controller.start(get_full_path(vmid))
			end
		end
	end

	def stop_lab_vm(vmid)
		if !running?(vmid)
			self.list_lab_running
		else
			@controller.stop(get_full_path(vmid))
		end
	end

	def start_lab
		@labdef.each { | key, value |
			if value
				self.start_lab_vm(key)
			end
		}
	end

	def pause_lab
		@labdef.each { | key, value |
			if value
				self.pause_lab_vm(key)
			end

		}
	end


	def stop_lab
		@labdef.each { | key, value |
			if value
				self.stop_lab_vm(key)
			end
		}

	end

	def reset_lab
		@labdef.each { | key, value |
			if value
				self.reset_lab_vm(key)
			end
		}
	end


	def suspend_lab
		@labdef.each { | key, value |
			if value 
				self.suspend_lab_vm(key)
			end
		}
	end

	def snapshot_lab(snapshot)
		@labdef.each { | key, value |
			if value
				self.snapshot_lab_vm(key,snapshot)
			end
		}
	end

	def revert_lab(snapshot)
		@labdef.each { | key, value |
			if value
				self.revert_lab_vm(key,snapshot)
			end
		}
	end

        def run_command_on_lab(command)
                @labdef.each { | key, value |
                        if value
                                self.run_command_on_lab_vm(key, command)
                        end
                }
        end

	def copy_to_lab(file)	
		@labdef.each { | key, value |
			if value
				self.copy_to_lab_vm(key,file)
			end
		}
	end

	def copy_from_lab(file)	
		@labdef.each { | key, value | 
#			next unless line =~ /^#{@vmbase}(.*)/
			if value
				self.copy_from_lab_vm(key,file)
			end
		}
	end

	def copy_to_lab_vm(vmid,file)
		## handle linux
		
		guestpath  = ""
		
		if (@labdef[vmid]["os"] == "linux")
			guestpath = "/tmp/"
		else
			guestpath = "C:\\temp_msf\\\\" ## double-escaping because it's being used in a system command. 
		end

		name = File.basename(file)

		## if we've installed vm-tools on the box, use that to copy. if not, use scp
		if (@labdef[vmid]["tools"] == "true")			
			@controller.create_directory_in_guest(get_full_path(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"], guestpath)
			@controller.copy_file_to(get_full_path(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"],file, guestpath + name)
		else
			@controller.scp_copy_file_to(@labdef[vmid]["hostname"], @labdef[vmid]["user"], file, guestpath + name)
		end
	end
	
	def copy_from_lab_vm(vmid,file)
		hostpath = "/tmp/"

		name = File.basename(file.gsub("\\","/")) 

		@controller.copy_file_from(get_full_path(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"],file,hostpath + name)
	end
	
	def list_lab_running
		@controller.get_running	
	end

	def list_lab
		str = ""
		@labdef.sort.each { |key,val|

			if val != nil
				str = str + key.to_s + ": "  + val["file"].to_s + "\n"
			end
		 }
		return str
	end

        def find_lab_vm(search)
		str = ""
                @labdef.sort.each { |key,val|
                        if val != nil
				if (val["file"].to_s.downcase.index(search.downcase) != nil)
	                                str = str + key.to_s + ": "  + val["file"].to_s + "\n"
				end
                        end
                 }
		return str
        end

	def exists?(vmid)
		if get_full_path(vmid)
			return true
		end
		return false
	end

	def running?(vmid)
		if @controller.running?(get_full_path(vmid))
			return true
		end
		return false
	end

	def get_full_path(vmid)
		if @labdef[vmid]
			@labdef[vmid]["file"].to_s		## handle linux
		else
			nil
		end
	end
end
