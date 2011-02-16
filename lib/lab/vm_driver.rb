##
## $Id$
##
module Lab
module Drivers
class VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize(location)
	
		@location = location
		@host = host
		@user = user
		@credentials = credentials
		@type = ""
	
	end

	def register
	end
		
	def unregister
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

	def create_snapshot(snapshot)
	end

	def revert_snapshot(snapshot)
	end

	def delete_snapshot(snapshot)
	end

	def run_command(command, named_user=nil)	
	end
	
	def copy_from(from, to, named_user=nil)
	end
	
	def copy_to(from, to, named_user=nil)
	end

	def check_file_exists(file, named_user=nil)
	end

	def create_directory(directory, named_user=nil)
	end

=begin
	def ssh_exec(host, command, user)
		ssh_command = "ssh " + @user + "@" + @host + " " + command
		system_command(ssh_command)
	end

	def scp_from(host, user, from, to)
		vmrunstr = "scp -r \"" + @user + "@" + @host + ":" + from + "\" \"" + to + "\""  
		system_command(vmrunstr)
	end

	def scp_to(host, user, from, to)
		vmrunstr = "scp -r \"" + from + "\" \"" + @user + "@" + @host + ":" + to + "\""
		system_command(vmrunstr)
	end
=end

	def cleanup
	end

	private
	
		def filter_input(string)
			return unless string
					
			if !(string =~ /^[\w\s\[\]\{\}\/\\\.\-\"\(\)]*$/)
				raise Exception, "Invalid character in: #{string}"
			end

			#return string.gsub(/^[\w\s\[\]\{\}\/\\\.\-\"\(\)]*$/, "Invalid String")
		end

		def filter_input_credentials(credentials)
			return unless credentials
		
			credentials.each { |credential|
				credential['user'] = filter_input(credential['user'])
				credential['pass'] = filter_input(credential['pass'])
			}

			return credentials
		end

		
		## Takes a username in the form of a string
		## and returns a credentials hash
		def get_best_creds(named_user)
			if !@credentials.empty?
				return get_named_user_creds(named_user) || @credentials[0]	
			else
				raise Exception, "No credentials for this VM ):"
			end
		end

		
		## Checks the array of credentials to see if we have one
		## with this user's username. returns the first.
		def get_named_user_creds(user)
			cretdentials.each do |credential|
				if credential['user'].downcase == user.downcase
					return credential
				end
			end
			return nil
		end

		def system_command(command)
			puts "DEBUG: #{command}"
			system(command)
		end

end

end
end
