#!/usr/bin/ruby

require 'socket'

module Rex
module IO

###
#
# StreamAbstraction
# -----------------
#
# This class provides an abstraction to a stream based
# connection through the use of a streaming socketpair.
#
###
module StreamAbstraction

	# Creates a streaming socket pair
	def initialize_abstraction
		self.lsock, self.rsock = ::Socket.pair(::Socket::AF_UNIX,
				::Socket::SOCK_STREAM, 0)
	end

	attr_reader :lsock, :rsock
protected
	attr_writer :lsock, :rsock
end

end; end
