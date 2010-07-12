#$Id$

require 'find'
#
# Lower level methods which are ~generic to the vm software
#

## Crap class which wraps vmrun and gives us basic vm functionality 
class VmwareController

	def initialize
		puts "vmware server / workstations yo"
	end

	def start(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws start " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def stop(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws stop " + "\"" + vmx + "\"")
		else
			raise ArgumentError,"Couldn't find:  " + vmx, caller
		end
	end

	def suspend(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws suspend " + "\"" + vmx + "\"")
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def pause(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws pause " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def reset(vmx)
		if File.exist?(vmx)
			system_command("vmrun -T ws reset " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def run_command(vmx, command, user, pass, displayParameter=false)
		if File.exist?(vmx)

			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " runProgramInGuest \"" + vmx + "\" " + "\"" + command + "\" -interactive -noWait -activeWindow"
			@controller
			if displayParameter
				vmrunstr = vmrunstr + " -display :0"
			end

			system_command(vmrunstr)
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def copy_file_from(vmx, user, pass, guestpath, hostpath)
			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromGuestToHost \"" + vmx + "\" \"" + guestpath + "\" \"" + hostpath + "\"" 
			system_command(vmrunstr)
	end

	def copy_file_to(vmx, user, pass, hostpath, guestpath)
			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromHostToGuest \"" + vmx + "\" \"" + hostpath + "\" \"" + guestpath + "\""  
			system_command(vmrunstr)
	end

	def scp_copy_file_to(ip, user, pass, hostpath, guestpath)
			vmrunstr = "scp -r \"" + hostpath + "\" \"" + user + "@" + ip + ":" + guestpath + "\""  
			system_command(vmrunstr)
	end

	def check_file_exists(vmx, user, pass, file)
			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " fileExistsInGuest \"" + vmx + "\" \"" + file + "\" "
			system_command(vmrunstr)
	end

	def create_directory_in_guest(vmx, user, pass, directory)
			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " createDirectoryInGuest \"" + vmx + "\" \"" + directory + "\" "
			system_command(vmrunstr)
	end

	def create_snapshot(vmx, snapshot)
		if File.exist?(vmx)
			system_command("vmrun -T ws snapshot " + "\"" + vmx + "\" " + snapshot)
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def revert_snapshot(vmx, snapshot)
		if File.exist?(vmx)
			system_command("vmrun -T ws revertToSnapshot " + "\"" + vmx + "\" " + snapshot)
		else
			raise "Couldn't find: " + vmx, caller
		end
	end

	def delete_snapshot(vmx, snapshot)
		if File.exist?(vmx)
			system_command("vmrun -T ws deleteSnapshot " + "\"" + vmx + "\" " + snapshot )
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def get_running
		output = `vmrun list` ##hackity hack=begin
	end

	def running?(vmx)
		output = self.get_running

		output.each_line do |line| 
			next unless line =~ /^#{@vmbase}(.*)/
			return true if line.strip == vmx.strip
		end

		return false
	end

	private

	def system_command(command)
		system(command)
	end

end

#
# Higher level methods which are more specific to the types of things we want to do with a lab of machines
#
class LabController 

	attr_accessor :labdef
	attr_accessor :vmbase
	attr_accessor :controller

	def initialize (basepath = ".", labdef = Hash.new)
		@vmbase = basepath ## set the base directory for the lab (default to local)
		@labdef = labdef ## assign the lab definition if we were passed one (default to empty)

		## set up the controller. note that this is likely to change in the future (to provide for additional vm tech)
		@controller = VmwareController.new 
	end

	def build_lab_from_running(basepath=nil)
		@vmbase = basepath if basepath
		vm_array = self.get_running.split("\n")
		vm_array.shift
		stuff_array_info_lab(vm_array)
	end

	def build_lab_from_files(basepath=nil)
		@vmbase = basepath if basepath
		vm_array = Find.find(@vmbase).select { |f| 
			f =~ /\.vmx$/ && File.executable?(f)
		}
		stuff_array_into_lab(vm_array)
	end

	def stuff_array_into_lab(arr)
		return false unless arr.kind_of? Array
		arr.each_with_index {|v,i| 
			@labdef[i] = File.join(v.split(/[\x5c\x2f]+/))
			if @labdef[i] =~ /^#{@vmbase}(.*)/
				@labdef[i] = $1
			end
		}
		return @labdef
	end

	def run_command_on_lab_vm(vmid,command)
		begin	
			## handle linux
			display = false
			if (@labdef[vmid]["os"] == "linux")
				display=true
			end

			@controller.run_command(get_vmx(vmid), command , @labdef[vmid]["user"],@labdef[vmid]["pass"], display)

		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def start_lab_vm(vmid)
		if self.running?(vmid)
			puts vmid + " already started."
			self.list_running
		else
			begin	
				@controller.start(get_vmx(vmid)) 
			rescue Exception => e
				puts "error! " + e.to_s
			end 
		end
	end
	
	def reset_lab_vm(vmid)
		begin	
			@controller.reset(get_vmx(vmid))
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def pause_lab_vm(vmid)

		if !self.running?(vmid)
			puts vmid + " not started."
			self.list_running
		else
			begin	
				@controller.pause(get_vmx(vmid)) 
			rescue Exception => e
				puts "error! " + e.to_s
			end 
		end
	end

	def suspend_lab_vm(vmid)
		if !self.running?(vmid)
			puts vmid + " not started."
			self.list_running
		else
			begin	
				@controller.suspend(get_vmx(vmid))
			rescue Exception => e
				puts "error! " + e.inspect
			end 
		end
	end

	def snapshot_lab_vm(vmid, snapshot)
		if !self.running?(vmid)
			puts vmid + " not started."
			self.list_running
		else
			begin	
				@controller.create_snapshot(get_vmx(vmid),snapshot)
			rescue Exception => e
				puts "error! " + e.to_s
			end 
		end
	end

	def revert_lab_vm(vmid, snapshot)
		if !self.running?(vmid)
			puts vmid + " not started."
			self.list_running
		else
			begin	
				@controller.revert_snapshot(get_vmx(vmid),snapshot)
			rescue Exception => e
				puts "error! " + e.to_s
			end
		end
	end

	def stop_lab_vm(vmid)
		if !self.running?(vmid)
			puts vmid + " not started."
			self.list_running
		else
			begin	
				@controller.stop(get_vmx(vmid))
			rescue Exception => e
				puts "error! " + e.to_s
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
		
		guestpath = "C:\\temp\\"

		if (@labdef[vmid]["os"] == "linux")
			guestpath = "/tmp/"
		end
		
		name = File.basename(file) 	
	
		## if we've installed vm-tools on the box, use that to copy. if not, use scp
		if (@labdef[vmid]["tools"] == "true")
			@controller.create_directory_in_guest(get_vmx(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"], guestpath)

			begin	
				@controller.copy_file_to(get_vmx(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"],file, guestpath + name)
			rescue Exception => e
				puts "error! " + e.to_s
			end 
		else
			@controller.scp_copy_file_to(@labdef[vmid]["ip"], @labdef[vmid]["user"],@labdef[vmid]["pass"], file, guestpath + name)
		end
	end
	
	def copy_from_lab_vm(vmid,file)
		hostpath = "/tmp/"

		name = File.basename(file.gsub("\\","/")) 

		begin	
			@controller.copy_file_from(get_vmx(vmid),@labdef[vmid]["user"],@labdef[vmid]["pass"],file,hostpath + name)
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end
	
	def list_running
		@controller.get_running	
	end

	def list_lab
		str = ""
		@labdef.sort.each { |key,val|

			if val != nil
				str = str + key.to_s + ": "  + val["vmx"].to_s + "\n"
			end
		 }
		return str
	end

        def find_lab_vm(search)
		str = ""
                @labdef.sort.each { |key,val|
                        if val != nil
				if (val["vmx"].to_s.downcase.index(search.downcase) != nil)
	                                str = str + key.to_s + ": "  + val["vmx"].to_s + "\n"
				end
                        end
                 }
		return str
        end

	def running?(vmid)
		if @controller.running?(get_vmx(vmid))
			return true
		end
		return false
	end

	private

	def get_vmx(vmid)
		if @labdef[vmid]
			@vmbase.to_s + @labdef[vmid]["vmx"].to_s		## handle linux
		else
			raise "VM #{vmid} does not exist!"
		end
	end

end
