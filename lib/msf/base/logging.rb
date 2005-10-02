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
				'base',
			].each { |src|
				register_log_source(src, f)
			}
		end
	end

	#
	# Enables a log source.
	#
	def self.enable_log_source(src)
		f = Rex::Logging::Sinks::Flatfile.new(
			Msf::Config.log_directory + File::SEPARATOR + "#{src}.log")

		register_log_source(src, f)	
	end

	#
	# Stops logging for a given log source.
	#
	def self.disable_log_source(src)
		deregister_log_source(src)
	end

	#
	# Sets whether or not session logging is to be enabled.
	#
	def self.enable_session_logging(tf)
		@session_logging = tf
	end

	#
	# Returns whether or not session logging is enabled.
	#
	def self.session_logging_enabled?
		@session_logging || false
	end

	#
	# Starts logging for a given session.
	#
	def self.start_session_log(session)
		f = Rex::Logging::Sinks::Flatfile.new(
			Msf::Config.session_log_directory + File::SEPARATOR + "#{session.log_file_name}.log")

		register_log_source(session.log_source, f)
	end

	#
	# Stops logging for a given session.
	#
	def self.stop_session_log(session)
		deregister_log_source(session.log_source)
	end

end

end
