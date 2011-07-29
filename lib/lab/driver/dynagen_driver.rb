require 'vm_driver'

#
# $Id$
#

#
# To use this driver, you have to have a lab which is preconfigured. The best / easiest
# way i've found to to set up a lab is GNS3
# 

module Lab
module Drivers
	class DynagenDriver < VmDriver

		attr_accessor :type
		attr_accessor :location

		def initialize(vmid,location,platform)
			
			@vmid = filter_command(vmid)
			@location = filter_command(location)

			if !File.exist?(location)
				raise ArgumentError,"Couldn't find: " + location
			end

			@type = "dynagen"
			@running = false
			@platform = filter_command(platform)
			@credentials = []
		end

		def start
			# TODO - write the location-file to a temp-file 
			#        and set the autostart property 

			## start background dynamips process
			system_command("dynamips -H #{@platform} &")
			system_command("dynagen	#{@location}")
			@running = true
		end

		def stop
			system_command("killall dynagen")
			@running = false
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
