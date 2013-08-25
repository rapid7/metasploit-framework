# -*- coding: binary -*-
require 'socket'
require 'thread'
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


	#
	# Common Regular Expressions
	#

	MATCH_IPV6 = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/

	MATCH_IPV4 = /^\s*(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))\s*$/

	MATCH_IPV4_PRIVATE = /^\s*(?:10\.|192\.168|172.(?:1[6-9]|2[0-9]|3[01])\.|169\.254)/

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
		( addr =~ MATCH_IPV4 ) ? true : false
	end

	#
	# Determine whether this is an IPv6 address
	#
	def self.is_ipv6?(addr)
		( addr =~ MATCH_IPV6 ) ? true : false
	end

	#
	# Checks to see if the supplied address is in "dotted" form
	#
	def self.dotted_ip?(addr)
		# Match IPv6
		return true if (support_ipv6? and addr =~ MATCH_IPV6)

		# Match IPv4
		return true if (addr =~ MATCH_IPV4)

		false
	end

	#
	# Return true if +addr+ is within the ranges specified in RFC1918, or
	# RFC5735/RFC3927
	#
	def self.is_internal?(addr)
		if self.dotted_ip?(addr)
			addr =~ MATCH_IPV4_PRIVATE
		else
			false
		end
	end

	#
	# Wrapper for Resolv.getaddress that takes special care to see if the
	# supplied address is already a dotted quad, for instance.  This is
	# necessary to prevent calls to gethostbyaddr (which occurs on windows).
	# These calls can be quite slow. This also fixes an issue with the
	# Resolv.getaddress() call being non-functional on Ruby 1.9.1 (Win32).
	#
	def self.getaddress(addr, accept_ipv6 = true)
		begin
			if addr =~ MATCH_IPV4 or (accept_ipv6 and addr =~ MATCH_IPV6)
				return addr
			end

			res = ::Socket.gethostbyname(addr)
			return nil if not res

			# Shift the first three elements out
			rname  = res.shift
			ralias = res.shift
			rtype  = res.shift

			# Rubinius has a bug where gethostbyname returns dotted quads instead of
			# NBO, but that's what we want anyway, so just short-circuit here.
			if res[0] =~ MATCH_IPV4 || res[0] =~ MATCH_IPV6
				res.each { |r|
					# if the caller doesn't mind ipv6, just return whatever we have
					return r if accept_ipv6
					# otherwise, take the first v4 address
					return r if r =~ MATCH_IPV4
				}
				# didn't find one
				return nil
			end

			# Reject IPv6 addresses if we don't accept them
			if not accept_ipv6
				res.reject!{|nbo| nbo.length != 4}
			end

			# Make sure we have at least one name
			return nil if res.length == 0

			# Return the first address of the result
			self.addr_ntoa( res[0] )
		rescue ::ArgumentError # Win32 bug
			nil
		end
	end

	#
	# Wrapper for Resolv.getaddress that takes special care to see if the
	# supplied address is already a dotted quad, for instance.  This is
	# necessary to prevent calls to gethostbyaddr (which occurs on windows).
	# These calls can be quite slow. This also fixes an issue with the
	# Resolv.getaddress() call being non-functional on Ruby 1.9.1 (Win32).
	#
	def self.getaddresses(addr, accept_ipv6 = true)
		begin
			if addr =~ MATCH_IPV4 or (accept_ipv6 and addr =~ MATCH_IPV6)
				return [addr]
			end

			res = ::Socket.gethostbyname(addr)
			return [] if not res

			# Shift the first three elements out
			rname  = res.shift
			ralias = res.shift
			rtype  = res.shift

			# Reject IPv6 addresses if we don't accept them
			if not accept_ipv6
				res.reject!{|nbo| nbo.length != 4}
			end

			# Make sure we have at least one name
			return [] if res.length == 0

			# Return an array of all addresses
			res.map{ |addr| self.addr_ntoa(addr) }
		rescue ::ArgumentError # Win32 bug
			[]
		end
	end

	#
	# Wrapper for Socket.gethostbyname which takes into account whether or not
	# an IP address is supplied.  If it is, then reverse DNS resolution does
	# not occur.  This is done in order to prevent delays, such as would occur
	# on Windows.
	#
	def self.gethostbyname(host)
		if (is_ipv4?(host))
			return [ host, [], 2, host.split('.').map{ |c| c.to_i }.pack("C4") ]
		end

		if is_ipv6?(host)
			host, scope_id = host.split('%', 2)
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
		self.gethostbyname( Rex::Socket.getaddress(host, true) )[3]
	end

	#
	# Resolves a host to raw network-byte order.
	#
	def self.resolv_nbo_list(host)
		Rex::Socket.getaddresses(host).map{|addr| self.gethostbyname(addr)[3] }
	end

	#
	# Resolves a host to a network-byte order ruby integer.
	#
	def self.resolv_nbo_i(host)
		addr_ntoi(resolv_nbo(host))
	end

	#
	# Resolves a host to a list of network-byte order ruby integers.
	#
	def self.resolv_nbo_i_list(host)
		resolv_nbo_list(host).map{|addr| addr_ntoi(addr) }
	end

	#
	# Converts an ASCII IP address to a CIDR mask. Returns
	# nil if it's not convertable.
	#
	def self.addr_atoc(mask)
		mask_i = resolv_nbo_i(mask)
		cidr = nil
		0.upto(32) do |i|
			if ((1 << i)-1) << (32-i) == mask_i
				cidr = i
				break
			end
		end
		return cidr
	end

	#
	# Resolves a CIDR bitmask into a dotted-quad. Returns
	# nil if it's not convertable.
	#
	def self.addr_ctoa(cidr)
		return nil unless (0..32) === cidr.to_i
		addr_itoa(((1 << cidr)-1) << 32-cidr)
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
	# Converts a ascii address into a list of addresses
	#
	def self.addr_atoi_list(addr)
		resolv_nbo_i_list(addr)
	end

	#
	# Converts an integer address into ascii
	#
	def self.addr_itoa(addr, v6=false)

		nboa = addr_iton(addr, v6)

		# IPv4
		if (addr < 0x100000000 and not v6)
			addr_ntoa(nboa)
		# IPv6
		else
			addr_ntoa(nboa)
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
			return compress_address(addr.unpack('n8').map{ |c| "%x" % c }.join(":"))
		end

		raise RuntimeError, "Invalid address format"
	end

	#
	# Implement zero compression for IPv6 addresses.
	# Uses the compression method from Marco Ceresa's IPAddress GEM
	#	https://github.com/bluemonk/ipaddress/blob/master/lib/ipaddress/ipv6.rb
	#
	def self.compress_address(addr)
		return addr unless is_ipv6?(addr)
		addr = addr.dup
		while true
			break if addr.sub!(/\A0:0:0:0:0:0:0:0\Z/, '::')
			break if addr.sub!(/\b0:0:0:0:0:0:0\b/, ':')
			break if addr.sub!(/\b0:0:0:0:0:0\b/, ':')
			break if addr.sub!(/\b0:0:0:0:0\b/, ':')
			break if addr.sub!(/\b0:0:0:0\b/, ':')
			break if addr.sub!(/\b0:0:0\b/, ':')
			break if addr.sub!(/\b0:0\b/, ':')
			break
		end
		addr.sub(/:{3,}/, '::')
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
	# Converts a colon-delimited MAC address into a 6-byte binary string
	#
	def self.eth_aton(mac)
		mac.split(":").map{|c| c.to_i(16) }.pack("C*")
	end

	#
	# Converts a 6-byte binary string into a colon-delimited MAC address
	#
	def self.eth_ntoa(bin)
		bin.unpack("C6").map{|x| "%.2x" % x }.join(":").upcase
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
	#
	def self.bit2netmask(bitmask, ipv6=false)
		if bitmask > 32 or ipv6
			i = ((~((2 ** (128 - bitmask)) - 1)) & (2**128-1))
			n = Rex::Socket.addr_iton(i, true)
			return Rex::Socket.addr_ntoa(n)
		else
			[ (~((2 ** (32 - bitmask)) - 1)) & 0xffffffff ].pack('N').unpack('CCCC').join('.')
		end
	end


	def self.portspec_crack(pspec)
		portspec_to_portlist(pspec)
	end

	#
	# Converts a port specification like "80,21-23,443" into a sorted,
	# unique array of valid port numbers like [21,22,23,80,443]
	#
	def self.portspec_to_portlist(pspec)
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
		ports.sort.uniq.delete_if { |p| p < 1 or p > 65535 }
	end

	#
	# Converts a port list like [1,2,3,4,5,100] into a
	# range specification like "1-5,100"
	#
	def self.portlist_to_portspec(parr)
		ranges = []
		range  = []
		lastp  = nil

		parr.uniq.sort{|a,b| a<=>b}.map{|a| a.to_i}.each do |n|
			next if (n < 1 or n > 65535)
			if not lastp
				range = [n]
				lastp = n
				next
			end

			if lastp == n - 1
				range << n
			else
				ranges << range
				range = [n]
			end
			lastp = n
		end

		ranges << range
		ranges.delete(nil)
		ranges.uniq.map{|x| x.length == 1 ? "#{x[0]}" : "#{x[0]}-#{x[-1]}"}.join(",")
	end

	##
	#
	# Utility class methods
	#
	##

	#
	# This method does NOT send any traffic to the destination, instead, it uses a
	# "bound" UDP socket to determine what source address we would use to
	# communicate with the specified destination. The destination defaults to
	# Google's DNS server to make the standard behavior determine which IP
	# we would use to communicate with the internet.
	#
	def self.source_address(dest='8.8.8.8', comm = ::Rex::Socket::Comm::Local)
		begin
			s = self.create_udp(
				'PeerHost' => dest,
				'PeerPort' => 31337,
				'Comm'     => comm
			)
			r = s.getsockname[1]
			s.close

			# Trim off the trailing interface ID for link-local IPv6
			return r.split('%').first
		rescue ::Exception
			return '127.0.0.1'
		end
	end

	#
	# Identifies the link-local address of a given interface (if IPv6 is enabled)
	#
	def self.ipv6_link_address(intf)
		r = source_address("FF02::1%#{intf}")
		return if not (r and r =~ /^fe80/i)
		r
	end

	#
	# Identifies the mac address of a given interface (if IPv6 is enabled)
	#
	def self.ipv6_mac(intf)
		r = ipv6_link_address(intf)
		return if not r
		raw = addr_aton(r)[-8, 8]
		(raw[0,3] + raw[5,3]).unpack("C*").map{|c| "%.2x" % c}.join(":")
	end

	#
	# Create a TCP socket pair.
	#
	# sf: This create a socket pair using native ruby sockets and will work
	# on Windows where ::Socket.pair is not implemented.
	# Note: OpenSSL requires native ruby sockets for its io.
	#
	# Note: Even though sub-threads are smashing the parent threads local, there
	#       is no concurrent use of the same locals and this is safe.
	def self.tcp_socket_pair
		lsock   = nil
		rsock   = nil
		laddr   = '127.0.0.1'
		lport   = 0
		threads = []
		mutex   = ::Mutex.new

		threads << Rex::ThreadFactory.spawn('TcpSocketPair', false) {
			server = nil
			mutex.synchronize {
				threads << Rex::ThreadFactory.spawn('TcpSocketPairClient', false) {
					mutex.synchronize {
						rsock = ::TCPSocket.new( laddr, lport )
					}
				}
				server = ::TCPServer.new(laddr, 0)
				if (server.getsockname =~ /127\.0\.0\.1:/)
					# JRuby ridiculousness
					caddr, lport = server.getsockname.split(":")
					caddr = caddr[1,caddr.length]
					lport = lport.to_i
				else
					# Sane implementations where Socket#getsockname returns a
					# sockaddr
					lport, caddr = ::Socket.unpack_sockaddr_in( server.getsockname )
				end
			}
			lsock, saddr = server.accept
			server.close
		}

		threads.each { |t| t.join }

		return [lsock, rsock]
	end

	#
	# Create a UDP socket pair using native ruby UDP sockets.
	#
	def self.udp_socket_pair
		laddr = '127.0.0.1'

		lsock = ::UDPSocket.new
		lsock.bind( laddr, 0 )

		rsock = ::UDPSocket.new
		rsock.bind( laddr, 0 )

		rsock.connect( *lsock.addr.values_at(3,1) )

		lsock.connect( *rsock.addr.values_at(3,1) )

		return [lsock, rsock]
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
		Socket.from_sockaddr(super)
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

