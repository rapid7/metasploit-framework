#!/usr/bin/env ruby

require 'socket'
require 'fcntl'

module Rex
module IO

###
#
# This class provides an abstraction to a stream based
# connection through the use of a streaming socketpair.
#
###
module StreamAbstraction

	###
	#
	# Extension information for required Stream interface.
	#
	###
	module Ext

		#
		# Initializes peer information.
		#
		def initinfo(peer)
			@peer = peer
		end

		#
		# Symbolic peer information.
		#
		def peerinfo
			(@peer || "Remote Pipe")
		end

		#
		# Symbolic local information.
		#
		def localinfo
			"Local Pipe"
		end
	end

	#
	# This method creates a streaming socket pair and initializes it.
	#
	def initialize_abstraction
		self.lsock, self.rsock = Rex::Socket.socket_pair()
		self.lsock.extend(Rex::IO::Stream)
		self.lsock.extend(Ext)
		self.rsock.extend(Rex::IO::Stream)
	end

	#
	# This method cleans up the abstraction layer.
	#
	def cleanup_abstraction
		self.lsock.close if (self.lsock)
		self.rsock.close if (self.rsock)

		self.lsock = nil
		self.rsock = nil
	end

	#
	# Writes to the local side.
	#
	def syswrite(buffer)
		lsock.syswrite(buffer)
	end

	#
	# Reads from the local side.
	#
	def sysread(length)
		lsock.sysread(length)
	end

	#
	# Shuts down the local side of the stream abstraction.
	#
	def shutdown(how)
		lsock.shutdown(how)
	end

	#
	# Closes both sides of the stream abstraction.
	#
	def close
		cleanup_abstraction
	end

	#
	# Symbolic peer information.
	#
	def peerinfo
		"Remote-side of Pipe"
	end

	#
	# Symbolic local information.
	#
	def localinfo
		"Local-side of Pipe"
	end

	#
	# The left side of the stream.
	#
	attr_reader :lsock
	#
	# The right side of the stream.
	#
	attr_reader :rsock
protected
	attr_writer :lsock, :rsock # :nodoc:
end

end; end