require 'msf/core'

module Msf

###
#
# Handler
# -------
#
# This module acts as a base for all handler pseudo-modules.  They aren't
# really modules, so don't get the wrong idea champs!  They're merely
# mixed into dynamically generated payloads to handle monitoring for
# a connection.  Handlers are layered in between the base payload
# class and any other payload class.  A super cool ASCII diagram would
# look something like this
#
#      Module
#        ^
#        |
#     Payload
#        ^
#        |
#     Handler
#        ^
#        |
#      Stager
#        ^
#        |
#       Stage
#
###
module Handler

	#
	# Constants used with the ``handler'' method to indicate whether or not the
	# connection was used
	#
	Claimed = "claimed"
	Unused  = "unused"

	#
	# Returns the handler type
	#
	def self.handler_type
		return "none"
	end

	#
	# Sets up the connection handler
	#
	def setup_handler
	end

	#
	# Terminates the connection handler
	#
	def cleanup_handler
	end

	#
	# Start monitoring for a connection
	#
	def start_handler
	end

	#
	# Stop monitoring for a connection
	#
	def stop_handler
	end

	#
	# Checks to see if a payload connection has been established on
	# the supplied connection.  This is necessary for find-sock style 
	# payloads.
	#
	def handler(sock)
	end

	#
	# Handles an established connection supplied in the in and out 
	# handles.  The handles are passed as parameters in case this
	# handler is capable of handling multiple simultaneous 
	# connections.
	#
	def handle_connection(stream)
	end

	#
	# Wait just one second there!
	#
	def extra_delay
		sleep(1)
	end

protected

end

end
