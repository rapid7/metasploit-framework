require 'find'
require 'yaml'
require 'vmware_controller'
require 'qemu_controller'
require 'ec2_controller'

#
# ~Higher-level lab methods which are generic to the types of things we want to do with a lab of machines
#  Note that any generic vm functionality should be pushed down into the controller class. 

class LabController 

	attr_accessor :labdef
	attr_accessor :labbase
	attr_accessor :controller

	def initialize (labdef = nil, labbase = nil, labtype="vmware")

		if !labbase
			@labbase = "/opt/vm/"  ## set the base directory for the lab (default to local)
		else
			@labbase = labbase
		end
				
		if !labdef 
			 ## assign the default lab definition if we were not passed one
			@labdef = YAML::load_file(File.join(File.dirname(__FILE__), "..", "..", "data", "lab", "test_lab.yml" ))
		else
			@labdef = labdef
		end
		
		## handle yaml nils :/. turn them into blank strings.
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
		elsif labtype == "qemu"
			@controller = QemuController.new
			@file_extension = "img"
		elsif labtype == "ec2"
			@controller = Ec2Controller.new
		else
			raise "Invalid Lab Controller"
		end
	end

	def contains?(vmid)
		if get_full_path(vmid)
		 	true
	 	end
	end 
	
##TODO - these methods need some thought
	def build_lab_from_running(basepath=nil)
		@vmbase = basepath if basepath
		vm_array = self.get_running.split("\n") ## this should probably return an array
		vm_array.shift
		hlp_stuff_array_info_lab(vm_array)
	end

	def build_lab_from_files(basepath=nil)
		@vmbase = basepath if basepath
		vm_array = Find.find(@vmbase).select { |f| 
			f =~ /\.#{file_extension}$/ && File.executable?(f)
		}
		hlp_stuff_array_into_lab(vm_array)
	end

	def hlp_stuff_array_into_lab(arr)
		return false unless arr.kind_of? Array
		arr.each_with_index {|v,i| 
			@labdef[i] = File.join(v.split(/[\x5c\x2f]+/))
			if @labdef[i] =~ /^#{@vmbase}(.*)/
				@labdef[i] = $1
			end
		}
		return @labdef
	end
## TODO ^^

	def run_command_on_lab_vm(vmid,command,arguments=nil)
		begin	
			if @labdef[vmid]["tools"]
				@controller.run_command(get_full_path(vmid), command, @labdef[vmid]["user"],@labdef[vmid]["pass"])
			else
				if @labdef[vmid]["os"] == "linux"
					@controller.run_ssh_command(@labdef[vmid]["hostname"], command , @labdef[vmid]["user"])
				else
					raise Exception "OS Not Supported"
				end
			end
		rescue Exception => e
			print_error "error! " + e.to_s
		end 
	end

	def run_browser_on_lab_vm(vmid,uri)
		if @labdef[vmid]["os"] == "linux"
			command = "firefox " + uri
		elsif @labdef[vmid]['os'] == "windows"
			command = "C:\\Progra~1\\intern~1\\iexplore.exe " + uri
		else
			print_error "Don't know how to browse to '" + uri + "'."
		end
		run_command_on_lab_vm(vmid,command)
	end

	def start_lab_vm(vmid)
		if running?(vmid)
			self.list_lab_running
		else
			begin	
				@controller.start(get_full_path(vmid)) 
			rescue Exception => e
				print_error "error! " + e.to_s
			end 
		end
	end
	
	def reset_lab_vm(vmid)
		begin	
			@controller.reset(get_full_path(vmid))
		rescue Exception => e
			return "error! " + e.to_s
		end 
	end

	def pause_lab_vm(vmid)
		if !running?(vmid)
			self.list_lab_running
		else
			begin	
				@controller.pause(get_full_path(vmid)) 
			rescue Exception => e
				return "error! " + e.to_s
			end 
		end
	end

	def suspend_lab_vm(vmid)
		if !running?(vmid)
			self.list_lab_running
		else
			begin	
				@controller.suspend(get_full_path(vmid))
			rescue Exception => e
				return "error! " + e.inspect
			end 
		end
	end

	def snapshot_lab_vm(vmid, snapshot)
		if !running?(vmid)
			self.list_lab_running
		else
			begin	
				@controller.create_snapshot(get_full_path(vmid),snapshot)
			rescue Exception => e
				return "error! " + e.to_s
			end 
		end
	end

	def revert_lab_vm(vmid, snapshot)
		if !running?(vmid)
			self.list_lab_running
		else
			begin	
				@controller.revert_snapshot(get_full_path(vmid),snapshot)
			rescue Exception => e
				print_error "error! " + e.to_s
			end
		end
	end

	def stop_lab_vm(vmid)
		if !running?(vmid)
			self.list_lab_running
		else
			begin	
				@controller.stop(get_full_path(vmid))
			rescue Exception => e
				print_error "error! " + e.to_s
			end
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
			next unless line =~ /^#{@vmbase}(.*)/
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
			
			puts "DEBUG: creating directory: " + guestpath
			@controller.create_directory_in_guest(get_full_path(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"], guestpath)

			begin	
				puts "DEBUG: copying file: " + file + " into " + guestpath + name
				@controller.copy_file_to(get_full_path(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"],file, guestpath + name)
			rescue Exception => e
				print_error "error! " + e.to_s
			end 
		else
			puts "DEBUG: scp copying file: " + file + " into " + guestpath + name
			@controller.scp_copy_file_to(@labdef[vmid]["hostname"], @labdef[vmid]["user"], file, guestpath + name)
		end
	end
	
	def copy_from_lab_vm(vmid,file)
		hostpath = "/tmp/"

		name = File.basename(file.gsub("\\","/")) 

		begin	
			@controller.copy_file_from(get_full_path(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"],file,hostpath + name)
		rescue Exception => e
			print_error "error! " + e.to_s
		end 
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
			@labbase.to_s + @labdef[vmid]["file"].to_s		## handle linux
		else
			nil
		end
	end

end
