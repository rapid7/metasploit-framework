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
	# Determine whether this is an IPv4 address
	#	
	def self.is_ipv4?(addr)
		res = Rex::Socket.getaddress(addr)
		res.match(/:/) ? false : true
	end
	
	#
	# Determine whether this is an IPv6 address
	#		
	def self.is_ipv6?(addr)
		res = Rex::Socket.getaddress(addr)
		res.match(/:/) ? true : false
	end

	#
	# Checks to see if the supplied address is a dotted quad. 
	# TODO: IPV6
	#
	def self.dotted_ip?(addr)
		(addr =~ /\d+\.\d+\.\d+\.\d+/) ? true : false
	end

	#
	# Wrapper for Resolv.getaddress that takes special care to see if the
	# supplied address is already a dotted quad, for instance.  This is
	# necessary to prevent calls to gethostbyaddr (which occurs on windows).
	# These calls can be quite slow.
	#
	def self.getaddress(addr)
		dotted_ip?(addr) ? addr : Resolv.getaddress(ip)
	end

	#
	# Wrapper for Socket.gethostbyname which takes into account whether or not
	# an IP address is supplied.  If it is, then reverse DNS resolution does
	# not occur.  This is done in order to prevent delays, such as would occur
	# on Windows.
	#
	def self.gethostbyname(host)
		dotted_ip?(addr) ? [ host, host, 2, host.split('.').pack('C*') ] : ::Socket.gethostbyname(host)
	end

	#
	# Create a sockaddr structure using the supplied IP address, port, and
	# address family
	#
	def self.to_sockaddr(ip, port)
		ip   = "0.0.0.0" unless ip
		ip   = Rex::Socket.getaddress(ip)
		af   = ip.match(/:/) ? ::Socket::AF_INET6 : ::Socket::AF_INET
		
		if (af == ::Socket::AF_INET)
			data = [ af, port.to_i ] + ip.split('.').collect { |o| o.to_i } + [ "" ]
			return data.pack('snCCCCa8')
		end
		
		if (af == ::Socket::AF_INET6)
			data = [af, port.to_i, 0, self.gethostbyname(ip)[3], 0]
			return data.pack('snNa16N')
		end
		
		raise RuntimeError, "Invalid address family"
	end

	#
	# Returns the address family, host, and port of the supplied sockaddr as
	# [ af, host, port ]
	#
	def self.from_sockaddr(saddr)
		up = saddr.unpack('snA*')
		af   = up.shift
		port = up.shift

		case af
			when ::Socket::AF_INET
				return [ af, up.shift.unpack('C*').join('.'), port ]
				
			when ::Socket::AF_INET6
				return [ af, up.shift.unpack('H*').gsub(/(....)/){ |r| r << ':' }.sub(/:$/, ''), port ]
		end
		
		raise RuntimeError, "Invalid address family"
	end

	#
	# Resolves a host to raw network-byte order.
	# TODO: All this to work with IPV6 sockets
	
	def self.resolv_nbo(host)
		self.gethostbyname(Rex::Socket.getaddress(host))[3]
	end

	#
	# Resolves a host to a network-byte order ruby integer.
	#
	def self.resolv_nbo_i(host)
		ret = resolv_nbo(host).unpack('N*')
		case ret.length
			when 1
				return ret[0]
			when 4
				val = 0
				ret.each_index { |i| val += (  ret[i] << (96 - (i * 32)) ) }
				return val
			else
				raise RuntimeError, "Invalid address format"
		end
	end

	#
	# Resolves a host to a dotted address.
	#
	def self.resolv_to_dotted(host)
		Rex::Socket.getaddress(host)
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
		begin
			return self.create_udp(
				'PeerHost' => dest,
				'PeerPort' => 31337
			).getsockname[1]
		rescue ::Exception
			return '127.0.0.1'
		end
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
