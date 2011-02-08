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
			@type = "ec2"
		end

		def filter_input(string)
		
			if !(string =~ /^[[:alnum:]\/\\\-\.\(\)\ _]*$/)
				raise ArgumentError,"Invalid character in: #{string}"
			end

			return string.gsub(/^[^[:alnum:]\/\\\-\.\(\)\ _]*$/, '')
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

		def snapshot(name)
		end

		def revert(name)
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
			## Get running Vms
			running = `dynagen ?` #TODO
			running_array = running.split("\n")

			## Skip the first 4 lines of output
			4.times { running_array.shift } 

			running_array.each do |vmx|
				if vmx.to_s == @location.to_s
					return true
				end
			end

			return false
		end
	end
end
end
