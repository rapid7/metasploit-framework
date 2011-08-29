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
		def initialize(config,dynagen_config)
			super(config)
			@running = false
			@dynagen_platform = filter_command(dynagen_config['dynagen_platform'])
		end

		def start
			# TODO - write the location-file to a temp-file 
			#        and set the autostart property 

			## start background dynamips process
			system_command("dynamips -H #{@dynagen_platform} &")
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
