# -*- coding: binary -*-
module Msf
module Ui

#
# Common functions needed by more than one user interface
#
class Common

	# Process the command line argument vector, handling common global
	# var/value pairs that can be used to control additional framework
	# features
	def self.process_cli_arguments(framework, argv)
		argv.delete_if { |assign|
			var, val = assign.split('=', 2)

			next if var.nil? or val.nil?

			case var.downcase
				# Add an additional module search path
				when "modulepath"
					# Don't affect the module cache by us loading these modules
					framework.modules.add_path(val)
					true
				else
					false
			end
		}
	end

end

end
end
