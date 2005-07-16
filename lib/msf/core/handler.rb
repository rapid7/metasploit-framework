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
	# Initializes the session waiter event and other fun stuff.
	#
	def initialize(info = {})
		super

		# Create the waiter event with auto_reset set to false so that
		# if a session is ever created, waiting on it returns immediately.
		self.session_waiter_event = Rex::Sync::Event.new(false, false)
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
	# connections.  The default implementation simply creates a 
	# session using the payload's session factory reference and
	# the supplied stream.
	#
	def handle_connection(conn)
		# If the payload we merged in with has an associated session factory, 
		# allocate a new session.
		if (self.session)
			s = self.session.new(conn)

			# If the session is valid, register it with the framework and
			# notify any waiters we may have.
			if (s)
				register_session(s)
			end	
		end
	end

	#
	# The amount of time to wait for a session to come in.
	#
	def wfs_delay
		1
	end

	#
	# Waits for a session to be created as the result of a handler connection
	# coming in.  The return value is a session object instance on success or
	# nil if the timeout expires
	#
	def wait_for_session(t = wfs_delay)
		session = nil

		begin
			session = session_waiter_event.wait(t)
		rescue ::TimeoutError
		end		
		
		return session
	end

protected

	#
	# Registers a session with the framework and notifies any waiters of the
	# new session.
	#
	def register_session(session)
		session_waiter_event.notify(session)

		# TODO: register with the framework
	end

	attr_accessor :session_waiter_event

end

end
