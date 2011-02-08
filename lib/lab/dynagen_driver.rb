require 'vm_driver'

##
## $Id$
##

## To use this driver, you have to have a lab which is preconfigured. The best / easies
## way to set up a lab is to use GNS3 to configure it 
## 



module Lab
module Drivers
	class DynagenDriver < VmDriver

		attr_accessor :type
		attr_accessor :location

		def initialize(location)
			if !File.exist?(location)
				raise ArgumentError,"Couldn't find: " + location
			end

			@location = filter_input(location)
			@type = "dynagen"
			@running = false

			## start background dynamips process
			system_command("nice dynamips -H 7200 &")
		end

		def start
			## TODO - write the location-file to a temp-file and set the 
			## autostart property 

			system_command("dynagen	#{@location}")
			@running = true
		end

		def stop
			system_command("killall dynagen")
			@running = false
		end

		def suspend
			raise Exception, "Unsupported Command"
		end

		def pause
			raise Exception, "Unsupported Command"
		end

		def reset
			raise Exception, "Unsupported Command"
		end

		def snapshot(name)
			raise Exception, "Unsupported Command"
		end

		def revert(name)
			raise Exception, "Unsupported Command"
		end

		def delete_snapshot(name)
			raise Exception, "Unsupported Command"
		end

		def run_command(command, arguments, user, pass)
			raise Exception, "Unsupported Command"
		end

		def copy_from(user, pass, from, to)
			raise Exception, "Unsupported Command"
		end

		def copy_to(user, pass, from, to)
			raise Exception, "Unsupported Command"
		end

		def check_file_exists(user, pass, file)
			raise Exception, "Unsupported Command"
		end

		def create_directory(user, pass, directory)
			raise Exception, "Unsupported Command"
		end

		def cleanup

			`killall dynagen`
			`killall dynamips`
			@running = false
		end

		def running?
			return @running
		end
	end
end
end
