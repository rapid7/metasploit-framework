module Rex
module IO

###
#
# StreamServer
# ------------
#
# This mixin provides the framework and interface for implementing a streaming
# server that can listen for and accept stream client connections.
#
###
module StreamServer

	##
	#
	# Abstract methods
	#
	##

	#
	# Initiating listening on the stream server with the supplied parameters
	# which are specific to the stream server class instance.
	#
	def listen(params, opts = {})
	end

	#
	# Accepts an incoming stream connection and returns an instance of a
	# Stream-drived class.
	#
	def accept(opts = {})
	end

	#
	# Closes and shuts down the listener, cleaning up resources as necessary.
	#
	def close
	end

end

end 
end
