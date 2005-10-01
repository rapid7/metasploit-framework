require 'rex'
require 'msf/base'

module Msf

###
#
# Logging
# -------
#
# This module provides an initialization interface for logging.
#
###
class Logging

	#
	# Initialize logging
	#
	def self.init
		if (@initialized != true)
			@initialized = true

			f = Rex::Logging::Sinks::Flatfile.new(
				Msf::Config.log_directory + File::SEPARATOR + "framework.log")

			# Register each known log source
			[
				'rex',
				'core',
			].each { |src|
				register_log_source(src, f)
			}
		end
	end

end

end
