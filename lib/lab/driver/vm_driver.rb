##
## $Id$
##

#
# 	!!WARNING!! - All drivers are expected to filter input before running
#	anything based on it. This is particularly important in the case
#	of the drivers which wrap a command line program to provide 
# 	functionality.  
#

module Lab
module Drivers
class VmDriver

	def register	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end
		
	def unregister	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def start	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def stop	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def suspend	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def pause	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def resume	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def reset	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def create_snapshot(snapshot)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def revert_snapshot(snapshot)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def delete_snapshot(snapshot)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def run_command(command)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end
	
	def copy_from(from, to)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end
	
	def copy_to(from, to)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def check_file_exists(file)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def create_directory(directory)	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

	def cleanup	# Must be implemented in a child *_driver class
		raise "Command not Implemented"
	end

private

	# Currently this requires the net-ssh and net-scp gems. Ran into problems doing 
	# it with within metasploit (even though net-ssh is available). TODO - do something
	# about this...

	def scp_to(from,to)
		gem 'net-ssh'
		require 'net/ssh'
		
		gem 'net-scp'
		require 'net/scp'
		
		#begin
			# upload a file to a remote server
		Net::SCP.start(@vmid, @vm_user, :password => @vm_pass) do |scp|
			scp.upload!(from,to)
		end	
		#rescue Exception => e
		#	return false
		#end
	end
	
	def scp_from(from,to)
		gem 'net-ssh'
		require 'net/ssh'
		
		gem 'net-scp'
		require 'net/scp'
		
		#begin
		# download a file from a remote server
		Net::SCP.start(@vmid, @vm_user, :password => @vm_pass) do |scp|
			scp.download!(from,to)
		end	
		#rescue Exception => e
		#	return false
		#end

	end
	
	def ssh_exec(command)
		gem 'net-ssh'
		require 'net/ssh'

		#begin		
		Net::SSH.start(@vmid, @vm_user, :password => @vm_pass) do |ssh|
			result = ssh.exec!(command)
		end
		#rescue Exception => e
		#	return false
		#end

	end

	def filter_input(string)
		return "" unless string
				
		if !(string =~ /^[0-9\w\s\[\]\{\}\/\\\.\-\"\(\):!]*$/)
			raise "WARNING! Invalid character in: #{string}"
		end

	string
	end

	def filter_command(string)
		return "" unless string
				
		if !(string =~ /^[0-9\w\s\[\]\{\}\/\\\.\-\"\(\)]*$/)
			raise "WARNING! Invalid character in: #{string}"
		end

	string
	end
	
	def system_command(command)
		#begin
		system(command)
		#rescue	Exception => e
		#	return false
		#	end
	end
end

end
end
