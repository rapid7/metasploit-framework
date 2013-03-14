# -*- coding: binary -*-
require 'rex/socket'

module Rex
module Socket

###
#
# This mixin provides the basic interface that a derived class must implement
# in order to be a compatible comm class.  The base comm class also supports
# registering event handlers that can be notified when sockets are being
# created and have been created.  This allows code to extend sockets on
# creation from the single point that they are created.
#
###
module Comm

	###
	#
	# This mixin provides stubs for event notification handlers that can be
	# registered with a Comm factory to be called when various events occur,
	# such as socket instantiation.
	#
	###
	module Events

		#
		# This callback is notified when a socket is being created and is passed
		# the parameters that will be used to create it.
		#
		def on_before_socket_create(comm, param)
		end

		#
		# This callback is notified when a new socket is created and the
		# parameters that were used to create it.  This provides the callback
		# with a chance to extend or otherwise modify the socket before it's
		# passed on to the actual requestor.
		#
		def on_socket_created(comm, sock, param)
		end

	end

	#
	# Creates a compatible socket based on the supplied uniform parameters.
	#
	def self.create(param)
		raise NotImplementedError
	end

	#
	# Indicates whether or not this comm can be chained with other chainable
	# comms.  This is particularly important for things like Proxy Comms that
	# can be proxied through one another.  The semantics of this are currently
	# undefined and will probably need some more thought.
	#
	def chainable?
		false
	end

	#
	# Registers an event handler that implements the Rex::Socket::Comm::Event
	# interface in at least some fashion.  Event handlers are notified when
	# sockets are created through the Comm instance that they register against.
	#
	def register_event_handler(handler)
		if (handlers == nil)
			self.handlers        = []
		end

		self.handlers << handler
	end

	#
	# Deregisters a previously registered event handler.
	#
	def deregister_event_handler(handler)
		if (handlers)
			handlers.delete(handler)
		end
	end

	#
	# Enumerates each registered event handler so that they can be notified of
	# an event.
	#
	def each_event_handler(&block)
		if (handlers)
			handlers.each(&block)
		end
	end

	#
	# Notifies handlers of the before socket create event.
	#
	def notify_before_socket_create(comm, param)
		each_event_handler() { |handler|
			handler.on_before_socket_create(comm, param)
		}
	end

	#
	# Notifies handlers of the socket created event.
	#
	def notify_socket_created(comm, sock, param)
		each_event_handler() { |handler|
			handler.on_socket_created(comm, sock, param)
		}
	end

protected

	attr_accessor :handlers # :nodoc:
	attr_accessor :handlers_rwlock # :nodoc:

end

end
end
