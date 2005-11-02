require 'rex/socket'

###
#
# This class represents the set of parameters that are used to create
# a socket, whether it be a server or client socket.
#
###
class Rex::Socket::Parameters

	##
	#
	# Factory
	#
	##
	
	def self.from_hash(hash)
		return self.new(hash)
	end

	##
	#
	# Constructor
	#
	##

	# Initializes the attributes from the supplied hash
	def initialize(hash)
		if (hash['PeerHost'])
			self.peerhost = hash['PeerHost']
		elsif (hash['PeerAddr'])
			self.peerhost = hash['PeerHost']
		else
			self.peerhost = nil
		end

		if (hash['LocalHost'])
			self.localhost = hash['LocalHost']
		elsif (hash['LocalAddr'])
			self.localhost = hash['LocalAddr']
		else
			self.localhost = '0.0.0.0'
		end

		if (hash['PeerPort'])
			self.peerport = hash['PeerPort'].to_i
		else
			self.peerport = 0
		end

		if (hash['LocalPort'])
			self.localport = hash['LocalPort'].to_i
		else
			self.localport = 0
		end

		if (hash['Bare'])
			self.bare = hash['Bare']
		else
			self.bare = false
		end

		if (hash['SSL'])
			self.ssl = hash['SSL']
		else
			self.ssl = false
		end

		# The protocol this socket will be using
		if (hash['Proto'])
			self.proto = hash['Proto'].downcase
		else
			self.proto = 'tcp'
		end

		# Whether or not the socket should be a server
		self.server    = hash['Server'] || false

		# The communication subsystem to use to create the socket
		self.comm      = hash['Comm']

		# If no comm was supplied, try to use the comm that is best fit to
		# handle the provided host based on the current routing table.
		if (self.comm == nil and hash['PeerHost'])
			self.comm = Rex::Socket::SwitchBoard.best_comm(hash['PeerHost'])
		end

		# If we still haven't found a comm, we default to the local comm.
		self.comm      = Rex::Socket::Comm::Local if (self.comm == nil)

		# The number of connection retries to make (client only)
		self.retries   = hash['Retries'] || 0
	end

	##
	#
	# Conditionals
	#
	##

	def server?
		return (server == true)
	end

	def client?
		return (server == false)
	end

	def tcp?
		return (proto == 'tcp')
	end

	def udp?
		return (proto == 'udp')
	end

	def bare?
		return (bare == true)
	end

	def ssl?
		return ssl
	end

	##
	#
	# Attributes
	#
	##
	
	attr_accessor :peerhost, :peerport
	attr_accessor :localhost, :localport
	attr_accessor :proto, :server, :comm
	attr_accessor :retries, :bare, :ssl

	##
	#
	# Synonyms
	#
	##
	
	alias peeraddr  peerhost
	alias localaddr localhost

end
