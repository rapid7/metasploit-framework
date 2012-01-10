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
	
	def initialize(config)
	
		@vmid = filter_command(config["vmid"].to_s)
		@location = filter_command(config["location"])
		@credentials = config["credentials"] || []
		@tools = filter_input(config["tools"])

		@os = filter_input(config["os"])
		@hostname = filter_input(config["hostname"]) || filter_input(config["vmid"].to_s)

		# Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user'])
			@vm_pass = filter_input(@credentials[0]['pass'])
			@vm_keyfile = filter_input(@credentials[0]['keyfile'])
		end
	end

	## This interface must be implemented in a child driver class
	## #########################################################

	def register
		raise "Command not Implemented"
	end
		
	def unregister
		raise "Command not Implemented"
	end

	def start
		raise "Command not Implemented"
	end

	def stop
		raise "Command not Implemented"
	end

	def suspend
		raise "Command not Implemented"
	end

	def pause
		raise "Command not Implemented"
	end

	def resume
		raise "Command not Implemented"
	end

	def reset
		raise "Command not Implemented"
	end

	def create_snapshot(snapshot)
		raise "Command not Implemented"
	end

	def revert_snapshot(snapshot)
		raise "Command not Implemented"
	end

	def delete_snapshot(snapshot)
		raise "Command not Implemented"
	end

	def run_command(command)	
		raise "Command not Implemented"
	end

	def copy_from_guest(from, to)
		raise "Command not Implemented"
	end

	def copy_to_guest(from, to)
		raise "Command not Implemented"
	end

	def check_file_exists(file)
		raise "Command not Implemented"
	end

	def create_directory(directory)
		raise "Command not Implemented"
	end

	def cleanup
		raise "Command not Implemented"
	end

	## End Interface
	## #########################################################

private

	def scp_to(local,remote)
		#require 'net/scp'
		#::Net::SCP.start(@hostname, @vm_user, :password => @vm_pass) do |scp|
		#	scp.upload!(from,to)
		#end	
		system_command("scp #{local} #{@vm_user}@#{@hostname}:#{remote}")
	end
	
	def scp_from(local,remote)
		#require 'net/scp'
		# download a file from a remote server
		#::Net::SCP.start(@hostname, @vm_user, :password => @vm_pass) do |scp|
		#	scp.download!(from,to)
		#end
		system_command("scp #{@vm_user}@#{@hostname}:#{remote} #{local}")
	end

	def ssh_exec(command)
		::Net::SSH.start(@hostname, @vm_user, :password => @vm_pass) do |ssh|
			result = ssh.exec!(command)
		end
		`scp #{@vm_user}@#{@hostname} from to`
	end

	def filter_input(string)
		return "" unless string # nil becomes empty string
		return string unless string.class == String # Allow other types unmodified
		
		unless /^[\d\w\s\[\]\{\}\/\\\.\-\"\(\):!]*$/.match string
			raise "WARNING! Invalid character in: #{string}"
		end
	string
	end

	def filter_command(string)
		return "" unless string # nil becomes empty string
		return unless string.class == String # Allow other types unmodified		
		
		unless /^[\d\w\s\[\]\{\}\/\\\.\-\"\(\)]*$/.match string
			raise "WARNING! Invalid character in: #{string}"
		end
	string
	end

	# The only reason we don't filter here is because we need
	# the ability to still run clean (controlled entirely by us)
	# command lines.
	def system_command(command)
		`#{command}`
	end


	def remote_system_command(command)
		system_command("ssh #{@user}@#{@host} \"#{command}\"")
	end
end

end
end
