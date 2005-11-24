require 'socket'
require 'resolv'
require 'rex/exceptions'

module Rex

###
#
# Base class for all sockets.
#
###
module Socket

	module Comm
	end

	require 'rex/socket/parameters'
	require 'rex/socket/tcp'
	require 'rex/socket/tcp_server'

	require 'rex/socket/comm'
	require 'rex/socket/comm/local'
	
	require 'rex/socket/switch_board'
	require 'rex/socket/subnet_walker'

	##
	#
	# Factory methods
	#
	##

	#
	# Create a socket instance using the supplied parameter hash.
	#
	def self.create(opts = {})
		return create_param(Rex::Socket::Parameters.from_hash(opts))
	end

	#
	# Create a socket using the supplied Rex::Socket::Parameter instance.
	#
	def self.create_param(param)
		return param.comm.create(param)
	end

	#
	# Create a TCP socket using the supplied parameter hash.
	#
	def self.create_tcp(opts = {})
		return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'tcp')))
	end

	#
	# Create a TCP server socket using the supplied parameter hash.
	#
	def self.create_tcp_server(opts = {})
		return create_tcp(opts.merge('Server' => true))
	end

	#
	# Create a UDP socket using the supplied parameter hash.
	#
	def self.create_udp(opts = {})
		return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'udp')))
	end

	##
	#
	# Serialization
	#
	##

	#
	# Create a sockaddr structure using the supplied IP address, port, and
	# address family
	#
	def self.to_sockaddr(ip, port, af = ::Socket::AF_INET)
		ip   = "0.0.0.0" unless ip
		ip   = Resolv.getaddress(ip)
		data = [ af, port.to_i ] + ip.split('.').collect { |o| o.to_i } + [ "" ]

		return data.pack('snCCCCa8')
	end

	#
	# Returns the address family, host, and port of the supplied sockaddr as
	# [ af, host, port ]
	#
	def self.from_sockaddr(saddr)
		up = saddr.unpack('snCCCC')

		af   = up.shift
		port = up.shift

		return [ af, up.join('.'), port ]
	end

	#
	# Resolves a host to raw network-byte order.
	#
	def self.resolv_nbo(host)
		return to_sockaddr(host, 0)[4,4]
	end

	#
	# Resolves a host to a network-byte order ruby integer.
	#
	def self.resolv_nbo_i(host)
		return resolv_nbo(host).unpack('N')[0]
	end

	#
	# Resolves a host to a dotted address.
	#
	def self.resolv_to_dotted(host)
		Resolv.getaddress(host)
	end

	#
	# Converts a netmask (255.255.255.240) into a bitmask (28).  This is the
	# lame kid way of doing it.
	#
	def self.net2bitmask(netmask)
		raw = resolv_nbo(netmask).unpack('N')[0]

		0.upto(31) { |bit|
			p = 2 ** bit
			return (32 - bit) if ((raw & p) == p)
		}

		0
	end

	#
	# Converts a bitmask (28) into a netmask (255.255.255.240)
	#
	def self.bit2netmask(bitmask)
		[ (~((2 ** (32 - bitmask)) - 1)) & 0xffffffff ].pack('N').unpack('CCCC').join('.')
	end

	##
	#
	# Utility class methods
	#
	##
	
	def self.source_address(dest='1.2.3.4')
		self.create_udp(
			'PeerHost' => dest,
			'PeerPort' => 31337
		).getsockname[1]
	end
	

	##
	#
	# Class initialization
	#
	##

	#
	# Initialize general socket parameters.
	#
	def initsock(params = nil)
		if (params)
			self.peerhost  = params.peerhost
			self.peerport  = params.peerport
			self.localhost = params.localhost
			self.localport = params.localport
			self.context   = params.context || {}
		end
	end

	#
	# By default, all sockets are themselves selectable file descriptors.
	#
	def fd
		self
	end

	#
	# Returns local connection information.
	#
	def getsockname
		return Socket.from_sockaddr(super)
	end

	#
	# Wrapper around getsockname
	#
	def getlocalname
		getsockname
	end

	#
	# Return peer connection information.
	#
	def getpeername
		return Socket.from_sockaddr(super)
	end

	#
	# The peer host of the connected socket.
	#
	attr_reader :peerhost
	#
	# The peer port of the connected socket.
	#
	attr_reader :peerport
	#
	# The local host of the connected socket.
	#
	attr_reader :localhost
	#
	# The local port of the connected socket.
	#
	attr_reader :localport
	#
	# Contextual information that describes the source and other
	# instance-specific attributes.  This comes from the param.context
	# attribute.
	#
	attr_reader :context

protected

	attr_writer :peerhost, :peerport, :localhost, :localport # :nodoc:
	attr_writer :context # :nodoc:

end

end

#
# Globalized socket constants
#
SHUT_RDWR = ::Socket::SHUT_RDWR
SHUT_RD   = ::Socket::SHUT_RD
SHUT_WR   = ::Socket::SHUT_WR
