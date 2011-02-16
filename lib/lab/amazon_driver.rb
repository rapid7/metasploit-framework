require 'vm_driver'

##
## $Id$
##

module Lab
module Drivers
	class AmazonDriver < VmDriver
		
		include Lab::Amazon_Controller

	
		attr_accessor :type
		attr_accessor :location

		def initialize(location, key, secret_key)
			if !File.exist?(location)
				raise ArgumentError,"Couldn't find: " + location
			end

			@access_key = key
			@secret_access_key = secret_key
			@location = filter_input(location)
			@type = "amazon"
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

		def create_snapshot(name)
		end

		def revert_snapshot(name)
		end

		def delete_snapshot(name)
		end

		def run_command(command, arguments, user, pass)
		end
	
		def copy_from(user, pass, from, to)
		end

		def copy_to(user, pass, from, to)
		end

		def check_file_exists(user, pass, file)
		end

		def create_directory(user, pass, directory)
		end

		def cleanup
		end

		def running?
			return false
		end
	end
end
end
