##
## $Id$
##

#
# 	!!WARNING!! - All drivers are expected to filter input before running
#	anything based on it. This is particularly important in the case
#	of the drivers which wrap a command line to provide functionality.  
#

module Lab
module Drivers
class VmDriver
	
	attr_accessor :vmid 
	attr_accessor :location
	attr_accessor :os
	attr_accessor :tools
	attr_accessor :credentials
	
	def initialize(basic_driver_config)
		@vmid = filter_command(basic_driver_config["vmid"])
		@location = filter_command(basic_driver_config["location"])
		@credentials = basic_driver_config["credentials"] || []
		@tools = filter_input(basic_driver_config["tools"])
		@os = filter_input(basic_driver_config["os"])

		# Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user'])
			@vm_pass = filter_input(@credentials[0]['pass'])
			@vm_keyfile = filter_input(@credentials[0]['keyfile'])
		end
	end

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

	def scp_to(from,to)
		require 'net/scp'

		Net::SCP.start(@vmid, @vm_user, :password => @vm_pass) do |scp|
			scp.upload!(from,to)
		end	
	end
	
	def scp_from(from,to)
		require 'net/scp'

		# download a file from a remote server
		Net::SCP.start(@vmid, @vm_user, :password => @vm_pass) do |scp|
			scp.download!(from,to)
		end
	end
	
	def ssh_exec(command)
		Net::SSH.start(@vmid, @vm_user, :password => @vm_pass) do |ssh|
			result = ssh.exec!(command)
		end
	end

	def filter_input(string)
		return "" unless string # nil becomes empty string
		return unless string.class == String # Allow other types unmodified
		
		if !(string =~ /^[0-9\w\s\[\]\{\}\/\\\.\-\"\(\):!]*$/)
			raise "WARNING! Invalid character in: #{string}"
		end

	string
	end

	def filter_command(string)
		return "" unless string # nil becomes empty string
		return unless string.class == String # Allow other types unmodified		
		
		if !(string =~ /^[0-9\w\s\[\]\{\}\/\\\.\-\"\(\)]*$/)
			raise "WARNING! Invalid character in: #{string}"
		end

	string
	end
	
	# The only reason we don't filter here is because we need
	# the ability to still run clean (controlled entirely by us)
	# command lines.
	def system_command(command)
		system(command)
	end
end

end
end
