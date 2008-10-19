require 'msf/core'

module Msf

###
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

	##
	#
	# Constants used with the ``handler'' method to indicate whether or not the
	# connection was used.
	#
	##

	#
	# Returned by handlers to indicate that a socket has been claimed for use
	# by the payload.
	#
	Claimed = "claimed"
	#
	# Returned by handlers to indicate that a socket has not been claimed for
	# use.
	#
	Unused  = "unused"

	#
	# Returns the handler type.
	#
	def self.handler_type
		return "none"
	end

	#
	# Returns the transport-independent handler type.
	#
	def self.general_handler_type
		"none"
	end

	#
	# Returns the handler's name, if any.
	#
	def handler_name
		module_info['HandlerName']
	end

	#
	# Initializes the session waiter event and other fun stuff.
	#
	def initialize(info = {})
		super

		# Initialize the pending_connections counter to 0
		self.pending_connections = 0

		# Create the waiter event with auto_reset set to false so that
		# if a session is ever created, waiting on it returns immediately.
		self.session_waiter_event = Rex::Sync::Event.new(false, false)
	end

	#
	# Sets up the connection handler.
	#
	def setup_handler
	end

	#
	# Terminates the connection handler.
	#
	def cleanup_handler
	end

	#
	# Start monitoring for a connection.
	#
	def start_handler
	end

	#
	# Start another connection monitor
	#
	def add_handler(opts={})
	end

	#
	# Stop monitoring for a connection.
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
	# connections.  The default behavior is to attempt to create a session for
	# the payload.  This path will not be taken for mutli-staged payloads.
	#
	def handle_connection(conn)
		create_session(conn)
	end

	#
	# The amount of time to wait for a session to come in.
	#
	def wfs_delay
		2
	end

	#
	# Waits for a session to be created as the result of a handler connection
	# coming in.  The return value is a session object instance on success or
	# nil if the timeout expires.
	#
	def wait_for_session(t = wfs_delay)
		session = nil

		begin
			session = session_waiter_event.wait(t)
		rescue ::TimeoutError
		end
		
		# If a connection has arrived, wait longer...
		if (pending_connections > 0)
			session = session_waiter_event.wait
		end
		
		return session
	end
	
	#
	# Set by the exploit module to configure handler
	#
	attr_accessor :exploit_config

	#
	# This will be non-nil if the handler has a parent payload that it
	# was spawned from.  Right now, this is only the case with generic
	# payloads.  The parent payload is used to create a session
	# rather than using the instance itself.
	#
	attr_accessor :parent_payload

protected

	#
	# Creates a session, if necessary, for the connection that's been handled.
	# Sessions are only created if the payload that's been mixed in has an
	# associated session.
	#
	def create_session(conn)
		# If there is a parent payload, then use that in preference.
		return parent_payload.create_session(conn) if (parent_payload)

		# If the payload we merged in with has an associated session factory, 
		# allocate a new session.
		if (self.session)
			s = self.session.new(conn)

			# Pass along the framework context
			s.framework = framework

			# Associate this session with this payload and with the
			# assoc_exploit, if this payload has one
			s.set_via(
				'Exploit' => assoc_exploit ? assoc_exploit.refname : nil,
				'Payload' => self.refname)

			# Call the payload's on_session handler.  We run this prior to
			# registering the session because the act of registering the session
			# may lead to the termination of this thread.
			on_session(s)

			# If the session is valid, register it with the framework and
			# notify any waiters we may have.
			if (s)
				register_session(s)
			end

			return s
		end
		
	end

	#
	# Registers a session with the framework and notifies any waiters of the
	# new session.
	#
	def register_session(session)
		# Register the session with the framework
		framework.sessions.register(session)

		# If there is an exploit associated with this payload, then let's notify
		# anyone who is interested that this exploit succeeded
		if assoc_exploit
			framework.events.on_exploit_success(assoc_exploit, session)
		end

		# Notify waiters that they should be ready to rock
		session_waiter_event.notify(session)

		# Decrement the pending connections counter now that we've processed
		# one session.
		self.pending_connections -= 1
	end

	attr_accessor :session_waiter_event # :nodoc:
	attr_accessor :pending_connections  # :nodoc:
	
end

end

# The default none handler
require 'msf/core/handler/none'