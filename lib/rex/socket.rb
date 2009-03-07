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
	require 'rex/socket/range_walker'

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

	#
	# Create a IP socket using the supplied parameter hash.
	#
	def self.create_ip(opts = {})
		return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'ip')))
	end
	
	##
	#
	# Serialization
	#
	##


	# Cache our IPv6 support flag
	@@support_ipv6 = nil
	
	#
	# Determine whether we support IPv6
	#		
	def self.support_ipv6?
		return @@support_ipv6 if not @@support_ipv6.nil?

		@@support_ipv6 = false
		
		if (::Socket.const_defined?('AF_INET6'))
			begin
				s = ::Socket.new(::Socket::AF_INET6, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)
				s.close
				@@support_ipv6 = true
			rescue
			end
		end
		
		return @@support_ipv6
	end
	
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
	#
	def self.dotted_ip?(addr)
		# Assume anything with a colon is IPv6
		return true if (support_ipv6? and addr =~ /:/)
		
		# Otherwise assume this is IPv4
		(addr =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$/) ? true : false
	end

	#
	# Wrapper for Resolv.getaddress that takes special care to see if the
	# supplied address is already a dotted quad, for instance.  This is
	# necessary to prevent calls to gethostbyaddr (which occurs on windows).
	# These calls can be quite slow.
	#
	def self.getaddress(addr)
		begin
			dotted_ip?(addr) ? addr : Resolv.getaddress(addr)
		rescue ::ArgumentError # Win32 bug
			nil
		end
	end

	#
	# Wrapper for Socket.gethostbyname which takes into account whether or not
	# an IP address is supplied.  If it is, then reverse DNS resolution does
	# not occur.  This is done in order to prevent delays, such as would occur
	# on Windows.
	#
	def self.gethostbyname(host)
		if (dotted_ip?(host))
			if (is_ipv4?(host))
				return [ host, host, 2, host.split('.').map{ |c| c.to_i }.pack("C4") ]
			end
		end

		::Socket.gethostbyname(host)
	end

	#
	# Create a sockaddr structure using the supplied IP address, port, and
	# address family
	#
	def self.to_sockaddr(ip, port)
		
		if (ip == '::ffff:0.0.0.0')
			ip = support_ipv6?() ? '::' : '0.0.0.0'
		end

		return ::Socket.pack_sockaddr_in(port, ip)
	end

	#
	# Returns the address family, host, and port of the supplied sockaddr as
	# [ af, host, port ]
	#
	def self.from_sockaddr(saddr)
		port, host = ::Socket::unpack_sockaddr_in(saddr)
		af = ::Socket::AF_INET
		if (support_ipv6?() and is_ipv6?(host))
			af = ::Socket::AF_INET6
		end
		return [ af, host, port ]
	end

	#
	# Resolves a host to raw network-byte order.
	#
	def self.resolv_nbo(host)
		self.gethostbyname(Rex::Socket.getaddress(host))[3]
	end

	#
	# Resolves a host to a network-byte order ruby integer.
	#
	def self.resolv_nbo_i(host)
		addr_ntoi(resolv_nbo(host))
	end

	#
	# Resolves a host to a dotted address.
	#
	def self.resolv_to_dotted(host)
		addr_ntoa(addr_aton(host))
	end

	#
	# Converts a ascii address into an integer
	#
	def self.addr_atoi(addr)
		resolv_nbo_i(addr)
	end

	#
	# Converts an integer address into ascii
	#
	def self.addr_itoa(addr, v6=false)
	
		nboa = addr_iton(addr, v6)
		
		# IPv4 
		if (addr < 0x100000000 and not v6)
			nboa.unpack('C4').join('.')
		# IPv6
		else
			nboa.unpack('n8').map{ |c| "%.4x" % c }.join(":")
		end		
	end

	#
	# Converts a ascii address to network byte order
	#
	def self.addr_aton(addr)
		resolv_nbo(addr)
	end

	#
	# Converts a network byte order address to ascii
	#
	def self.addr_ntoa(addr)
	
		# IPv4 
		if (addr.length == 4)
			return addr.unpack('C4').join('.')
		end
		
		# IPv6
		if (addr.length == 16)
			return addr.unpack('n8').map{ |c| "%.4x" % c }.join(":")
		end
		
		raise RuntimeError, "Invalid address format"		
	end

	#
	# Converts a network byte order address to an integer
	#
	def self.addr_ntoi(addr)
	
		bits = addr.unpack("N*")
		
		if (bits.length == 1)
			return bits[0]
		end
		
		if (bits.length == 4)
			val = 0
			bits.each_index { |i| val += (  bits[i] << (96 - (i * 32)) ) }
			return val
		end
		
		raise RuntimeError, "Invalid address format"
	end

	#
	# Converts an integer into a network byte order address
	#
	def self.addr_iton(addr, v6=false)
		if(addr < 0x100000000 and not v6)
			return [addr].pack('N')
		else
			w    = []
			w[0] = (addr >> 96) & 0xffffffff
			w[1] = (addr >> 64) & 0xffffffff
			w[2] = (addr >> 32) & 0xffffffff
			w[3] = addr & 0xffffffff
			return w.pack('N4')		
		end
	end
			
	#
	# Converts a CIDR subnet into an array (base, bcast)
	#
	def self.cidr_crack(cidr, v6=false)
		tmp = cidr.split('/')
		
		tst,scope = tmp[0].split("%",2)
		scope     = "%" + scope if scope
		scope   ||= ""

		addr = addr_atoi(tst)
		
		bits = 32
		mask = 0
		use6 = false
		
		if (addr > 0xffffffff or v6 or cidr =~ /:/)
			use6 = true
			bits = 128
		end
		
		mask = (2 ** bits) - (2 ** (bits - tmp[1].to_i))
		base = addr & mask

		stop = base + (2 ** (bits - tmp[1].to_i)) - 1
		return [self.addr_itoa(base, use6) + scope, self.addr_itoa(stop, use6) + scope]	
	end

	#
	# Converts a netmask (255.255.255.240) into a bitmask (28).  This is the
	# lame kid way of doing it.
	#
	def self.net2bitmask(netmask)
	
		nmask = resolv_nbo(netmask)
		imask = addr_ntoi(nmask)
		bits  = 32
		
		if (imask > 0xffffffff)
			bits = 128
		end

		0.upto(bits-1) do |bit|
			p = 2 ** bit
			return (bits - bit) if ((imask & p) == p)
		end
		
		0
	end
		
	#
	# Converts a bitmask (28) into a netmask (255.255.255.240)
	# TODO: IPv6 (use is ambiguous right now)
	#
	def self.bit2netmask(bitmask)
		[ (~((2 ** (32 - bitmask)) - 1)) & 0xffffffff ].pack('N').unpack('CCCC').join('.')
	end

	#
	# Converts a port specification like "80,21-23,443" into a sorted,
	# unique array of valid port numbers like [21,22,23,80,443]
	#
	def self.portspec_crack(pspec)
		ports = []

		# Build ports array from port specification
		pspec.split(/,/).each do |item|
			start, stop = item.split(/-/).map { |p| p.to_i }

			start ||= 0
			stop ||= item.match(/-/) ? 65535 : start

			start, stop = stop, start if stop < start

			start.upto(stop) { |p| ports << p }
		end

		# Sort, and remove dups and invalid ports
		ports.sort.uniq.delete_if { |p| p < 0 or p > 65535 }
	end

	##
	#
	# Utility class methods
	#
	##
	
	def self.source_address(dest='1.2.3.4')
		begin
			s = self.create_udp(
				'PeerHost' => dest,
				'PeerPort' => 31337
			)
			r = s.getsockname[1]
			s.close
			return r
		rescue ::Exception
			return '127.0.0.1'
		end
	end
	
	def self.socket_pair
		begin
			pair = ::Socket.pair(::Socket::AF_UNIX, ::Socket::SOCK_STREAM, 0)

		# Windows does not support Socket.pair, so we emulate it
		rescue ::NotImplementedError
			srv = TCPServer.new('localhost', 0)
			rsock = TCPSocket.new(srv.addr[3], srv.addr[1])
			lsock = srv.accept
			srv.close
			[lsock, rsock]
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
			self.ipv       = params.v6 ? 6 : 4
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
	# Returns a string that indicates the type of the socket, such as 'tcp'.
	#
	def type?
		raise NotImplementedError, "Socket type is not supported."
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
	# The IP version of the socket
	#
	attr_reader :ipv
	#
	# Contextual information that describes the source and other
	# instance-specific attributes.  This comes from the param.context
	# attribute.
	#
	attr_reader :context

protected

	attr_writer :peerhost, :peerport, :localhost, :localport # :nodoc:
	attr_writer :context # :nodoc:
	attr_writer :ipv # :nodoc:

end

end

#
# Globalized socket constants
#
SHUT_RDWR = ::Socket::SHUT_RDWR
SHUT_RD   = ::Socket::SHUT_RD
SHUT_WR   = ::Socket::SHUT_WR
