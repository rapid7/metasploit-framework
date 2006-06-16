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

	#
	# Creates an instance of the Parameters class using the supplied hash.
	#
	def self.from_hash(hash)
		return self.new(hash)
	end

	##
	#
	# Constructor
	#
	##

	#
	# Initializes the attributes from the supplied hash.  The following hash
	# keys can be specified.
	#
	# PeerHost / PeerAddr
	#
	# 	The remote host to connect to.
	#
	# PeerPort
	#
	# 	The remote port to connect to.
	#
	# LocalHost / LocalAddr
	#
	# 	The local host to communicate from, if any.
	#
	# LocalPort
	#
	# 	The local port to communicate from, if any.
	#
	# Bare
	#
	# 	Create a bare socket.
	#
	# Server
	#
	# 	Whether or not this should be a server.
	#
	# SSL
	#
	# 	Whether or not SSL should be used.
	#
	# Comm
	#
	# 	The underlying Comm class to use to create the socket for this parameter
	# 	set.
	#
	# Context
	#
	# 	A context hash that can allow users of this parameter class instance to
	# 	determine who is responsible for requesting that a socket be created.
	#
	# Retries
	#
	# 	The number of times a connection should be retryed.
	#
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

		if (hash['SSL'] and hash['SSL'].to_s =~ /^(t|y|1)/i)
			self.ssl = true
		else
			self.ssl = false
		end

		if hash['Proxies']
			self.proxies = hash['Proxies'].split('-').map{|a| a.strip}.map{|a| a.split(':').map{|b| b.strip}}
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

		# The context that was passed in, if any.
		self.context   = hash['Context'] || {}

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

	#
	# Returns true if this represents parameters for a server.
	#
	def server?
		return (server == true)
	end

	#
	# Returns true if this represents parameters for a client.
	#
	def client?
		return (server == false)
	end

	#
	# Returns true if the protocol for the parameters is TCP.
	#
	def tcp?
		return (proto == 'tcp')
	end

	#
	# Returns true if the protocol for the parameters is UDP.
	#
	def udp?
		return (proto == 'udp')
	end

	#
	# Returns true if the socket is a bare socket that does not inherit from
	# any extended Rex classes.
	#
	def bare?
		return (bare == true)
	end

	#
	# Returns true if SSL has been requested.
	#
	def ssl?
		return ssl
	end

	##
	#
	# Attributes
	#
	##

	#
	# The remote host information, equivalent to the PeerHost parameter hash
	# key.
	#
	attr_accessor :peerhost
	#
	# The remote port.  Equivalent to the PeerPort parameter hash key.
	#
	attr_accessor :peerport
	#
	# The local host.  Equivalent to the LocalHost parameter hash key.
	#
	attr_accessor :localhost
	#
	# The local port.  Equivalent to the LocalPort parameter hash key.
	#
	attr_accessor :localport
	#
	# The protocol to to use, such as TCP.  Equivalent to the Proto parameter
	# hash key.
	#
	attr_accessor :proto
	#
	# Whether or not this is a server.  Equivalent to the Server parameter hash
	# key.
	#
	attr_accessor :server
	#
	# The Comm class that should be used to create the underlying socket.
	#
	attr_accessor :comm
	#
	# The context hash that was passed in to the structure.
	#
	attr_accessor :context
	#
	# The number of attempts that should be made.
	#
	attr_accessor :retries
	#
	# Whether or not this is a bare (non-extended) socket instance that should
	# be created.
	#
	attr_accessor :bare
	#
	# Whether or not SSL should be used to wrap the connection.
	#
	attr_accessor :ssl


	attr_accessor :proxies


	##
	#
	# Synonyms
	#
	##
	
	alias peeraddr  peerhost
	alias localaddr localhost

end
