##
## $Id$
##

class VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(location)
	end

	def start
	end

	def stop
	end

	def suspend
	end

	def pause
	end

	def reset
	end

	def snapshot(snapshot)
	end

	def revert(snapshot)
	end

	def delete_snapshot(snapshot)
	end

	def run_command(command, user, pass)	
	end
	
	def copy_from(user, pass, from, to)
	end
	
	def copy_to(user, pass, from, to)
	end

	def check_file_exists(user, pass, file)
	end

	def create_directory(user, pass, directory)
	end

	def ssh_exec(host, command, user)
		ssh_command = "ssh " + user + "@" + host + " " + command
		system_command(ssh_command)
	end

	def scp_from(host, user, from, to)
		vmrunstr = "scp -r \"" + user + "@" + host + ":" + from + "\" \"" + to + "\"" ## TODO - setup keys  
		system_command(vmrunstr)
	end

	def scp_to(host, user, from, to)
		vmrunstr = "scp -r \"" + from + "\" \"" + user + "@" + host + ":" + to + "\"" ## TODO - setup keys  
		system_command(vmrunstr)
	end

	private

		def system_command(command)
			## TODO - filter here
			system(command)
		end

end
