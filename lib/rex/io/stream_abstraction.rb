#!/usr/bin/ruby

require 'socket'

module Rex
module IO

###
#
# This class provides an abstraction to a stream based
# connection through the use of a streaming socketpair.
#
###
module StreamAbstraction

	#
	# Creates a streaming socket pair
	#
	def initialize_abstraction
		self.lsock, self.rsock = ::Socket.pair(::Socket::AF_UNIX,
				::Socket::SOCK_STREAM, 0)

		self.lsock.extend(Rex::IO::Stream)
		self.rsock.extend(Rex::IO::Stream)
	end

	#
	# Cleans up the abstraction layer
	#
	def cleanup_abstraction
		self.lsock.close if (self.lsock)
		self.rsock.close if (self.rsock)

		self.lsock = nil
		self.rsock = nil
	end

	attr_reader :lsock, :rsock
protected
	attr_writer :lsock, :rsock
end

end; end
