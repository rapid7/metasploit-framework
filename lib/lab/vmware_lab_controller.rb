## Crap class which wraps vmrun

#
# Lower level methods which are ~generic to the vm software
#
class VmwareController

	def start(vmx)
		if File.exist?(vmx) then
			system_command("vmrun -T ws start " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def reset(vmx)
		if File.exist?(vmx) then
			system_command("vmrun -T ws reset " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	def get_running
		output = `vmrun list`
	end

	def running?(vmx)
		output = get_running

		output.each_line do |line| 
			if line.to_s.chomp.eql? vmx.to_s then return true end
		end

		return false
	end


	def run_command(vmx, command, user, pass, displayParameter=false)
		if File.exist?(vmx) then

			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " runProgramInGuest \"" + vmx + "\" " + "\"" + command + "\" -interactive -noWait -activeWindow"
			
			if displayParameter then 
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

			#puts "Copying " + hostpath + " to " + guestpath + " on " + vmx + "\n"

			vmrunstr = "vmrun -T ws -gu " + user + " -gp " + pass + " copyFileFromHostToGuest \"" + vmx + "\" \"" + hostpath + "\" \"" + guestpath + "\""  
			system_command(vmrunstr)
	end

	def scp_copy_file_to(ip, user, pass, hostpath, guestpath)

			#puts "Copying " + hostpath + " to " + guestpath + " on " + vmx + "\n"

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
		if File.exist?(vmx) then
			system_command("vmrun -T ws snapshot " + "\"" + vmx + "\" " + snapshot)
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def revert_snapshot(vmx, snapshot)
		if File.exist?(vmx) then
			system_command("vmrun -T ws revertToSnapshot " + "\"" + vmx + "\" " + snapshot)
		else
			raise "Couldn't find: " + vmx, caller
		end
	end

	def delete_snapshot(vmx, snapshot)
		if File.exist?(vmx) then
			system_command("vmrun -T ws deleteSnapshot " + "\"" + vmx + "\" " + snapshot )
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def stop(vmx)
		if File.exist?(vmx) then
			system_command("vmrun -T ws stop " + "\"" + vmx + "\"")
		else
			raise ArgumentError,"Couldn't find:  " + vmx, caller
		end
	end

	def suspend(vmx)
		if File.exist?(vmx) then
			system_command("vmrun -T ws suspend " + "\"" + vmx + "\"")
		else
			raise ArgumentError,"Couldn't find: " + vmx, caller
		end
	end

	def pause(vmx)
		if File.exist?(vmx) then
			system_command("vmrun -T ws pause " + "\"" + vmx + "\"")
		else
			raise ArgumentError, "Couldn't find: " + vmx, caller
		end
	end

	private

	def system_command(command)
		puts "Running System Command: " + command 	
		system(command)
	end
end

#
# Higher level methods which are specifc to the types of things we want to do
#
class VmwareLabController < VmwareController	

	def initialize (basepath = "." )
		@vmbase = basepath
		@lab = Hash.new()
	end

	def run_command_on_lab_vm(vmid,command)
		begin	
			## handle linux
			display = false
			if (@lab[vmid]["os"] == "linux") then
				display=true
			end

			run_command(get_vmx(vmid), command , @lab[vmid]["user"],@lab[vmid]["pass"], display)

		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def start_lab_vm(vmid)
		begin	
			start(get_vmx(vmid))
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end
	
	def reset_lab_vm(vmid)
		begin	
			reset(get_vmx(vmid))
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def pause_lab_vm(vmid)
		begin	
			pause(get_vmx(vmid))
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def suspend_lab_vm(vmid)
		begin	
			suspend(get_vmx(vmid))
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def snapshot_lab_vm(vmid, snapshot)
		begin	
			create_snapshot(get_vmx(vmid),snapshot)
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def revert_lab_vm(vmid, snapshot)
		begin	
			revert_snapshot(get_vmx(vmid),snapshot)
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def stop_lab_vm(vmid)
		begin	
			stop(get_vmx(vmid))
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end

	def start_lab
		@lab.each { | key, value |
			if value != nil then
				start_lab_vm(key)
			end
		}
	end

	def reset_lab
		@lab.each { | key, value |
			if value != nil then
				reset_lab_vm(key)
			end
		}
	end


	def suspend_lab
		@lab.each { | key, value |
			if value != nil then
				suspend_lab_vm(key)
			end
		}
	end

	def snapshot_lab(snapshot)
		@lab.each { | key, value |
			if value != nil then
				snapshot_lab_vm(key,snapshot)
			end
		}
	end

	def revert_lab(snapshot)
		@lab.each { | key, value |
			if value != nil then
				revert_lab_vm(key,snapshot)
			end
		}
	end

        def run_command_on_lab(command)
                @lab.each { | key, value |
                        if value != nil then
                                run_command_on_lab_vm(key, command)
                        end
                }
        end

	def pause_lab
		@lab.each { | key, value |
			if value != nil then
				pause_lab_vm(key)
			end

		}
	end

	def stop_lab
		@lab.each { | key, value |
			if value != nil then
				stop_lab_vm(key)
			end
		}

	end

	def revert_lab(snapshot)
		@lab.each { | key, value |
			if value != nil then
				revert_lab_vm(key, snapshot)
			end
		}
	end



	def copy_to_lab(file)	
		@lab.each { | key, value |
			if value != nil then
				copy_to_lab_vm(key,file)
			end
		}
	end

	def copy_from_lab(file)	
		@lab.each { | key, value |
			if value != nil then
				copy_from_lab_vm(key,file)
			end
		}
	end

	def copy_to_lab_vm(vmid,file)
		## handle linux
		
		guestpath = "C:\\temp2\\"

		if (@lab[vmid]["os"] == "linux") then
			guestpath = "/tmp/"
		end
		
		name = File.basename(file) 

		if (@lab[vmid]["tools"] == "true") then
			
			create_directory_in_guest(get_vmx(vmid),@lab[vmid]["user"],@lab[vmid]["pass"], guestpath)


			begin	
				copy_file_to(get_vmx(vmid),@lab[vmid]["user"],@lab[vmid]["pass"],file, guestpath + name)
			rescue Exception => e
				puts "error! " + e.to_s
			end 
		else
			scp_copy_file_to(@lab[vmid]["ip"], @lab[vmid]["user"],@lab[vmid]["pass"], file, guestpath + name)

		end

	end
	


	def copy_from_lab_vm(vmid,file)
		hostpath = "/tmp/"

		name = File.basename(file.gsub("\\","/")) 

		#puts "filenaem: " + name + "\n"

		begin	
			copy_file_from(get_vmx(vmid),@lab[vmid]["user"],@lab[vmid]["pass"],file,hostpath + name)
		rescue Exception => e
			puts "error! " + e.to_s
		end 
	end
	

	def list_lab
		str = ""
		@lab.map { |key,val| 
			if val != nil then
				str = str + key.to_s + ": "  + val["vmx"].to_s + "\n"
			end
		 }
	return str
	end

        def find_lab_vm(search)
                str = ""
                @lab.map { |key,val|
                        if val != nil then
				if (val["vmx"].to_s.downcase.index(search.downcase) != nil) then
	                                str = str + key.to_s + ": "  + val["vmx"].to_s + "\n"
				end
                        end
                 }
        return str
        end

	def running?(vmid)
		if super(get_vmx(vmid)) then
			return true
		end
		return false
	end

	private

	def get_vmx(vmid)
		if @lab[vmid] != nil then
			@vmbase.to_s + @lab[vmid]["vmx"].to_s		## handle linux
		else
			raise "VM " + vmid + " does not exist!"
		end
	end

end
