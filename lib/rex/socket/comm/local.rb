require 'singleton'
require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/socket/ssl_tcp'
require 'rex/socket/ssl_tcp_server'
require 'rex/socket/udp'
require 'rex/socket/ip'
require 'timeout'

###
#
# Local communication class factory.
#
###
class Rex::Socket::Comm::Local

	include Singleton
	include Rex::Socket::Comm

	#
	# Creates an instance of a socket using the supplied parameters.
	#
	def self.create(param)
		case param.proto
			when 'tcp'
				return create_by_type(param, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_TCP)
			when 'udp'
				return create_by_type(param, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)
			when 'ip'
				return create_ip(param)
			else
				raise Rex::UnsupportedProtocol.new(param.proto), caller
		end
	end


	#
	# Creates a raw IP socket using the supplied Parameter instance.
	# Special-cased because of how different it is from UDP/TCP
	#
	def self.create_ip(param)
		self.instance.notify_before_socket_create(self, param)

		sock = ::Socket.open(::Socket::PF_INET, ::Socket::SOCK_RAW, ::Socket::IPPROTO_RAW)
		sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_HDRINCL, 1)

		# Configure broadcast support
		sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BROADCAST, true)

		if (param.bare? == false)
			sock.extend(::Rex::Socket::Ip)
			sock.initsock(param)
		end

		self.instance.notify_socket_created(self, sock, param)

		sock
	end
	
	
	#
	# Creates a socket using the supplied Parameter instance.
	#
	def self.create_by_type(param, type, proto = 0)

		# Whether to use IPv6 addressing
		usev6 = false
			
		# Detect IPv6 addresses and enable IPv6 accordingly
		if ( Rex::Socket.support_ipv6?())

			# Allow the caller to force IPv6
			if (param.v6)
				usev6 = true
			end

			# Force IPv6 mode for non-connected UDP sockets
			if (type == ::Socket::SOCK_DGRAM and not param.peerhost)
				# FreeBSD allows IPv6 socket creation, but throws an error on sendto()
				
				if (not Rex::Compat.is_freebsd())
					usev6 = true
				end
			end
		
			local = Rex::Socket.resolv_nbo(param.localhost) if param.localhost
			peer  = Rex::Socket.resolv_nbo(param.peerhost) if param.peerhost
			
			if (local and local.length == 16)
				usev6 = true			
			end
			
			if (peer and peer.length == 16)
				usev6 = true			
			end
			
			if (usev6)
				if (local and local.length == 4)
					if (local == "\x00\x00\x00\x00")
						param.localhost = '::'
					elsif (local == "\x7f\x00\x00\x01")
						param.localhost = '::1'
					else
						param.localhost = '::ffff:' + Rex::Socket.getaddress(param.localhost)
					end
				end
				
				if (peer and peer.length == 4)
					if (peer == "\x00\x00\x00\x00")
						param.peerhost = '::'
					elsif (peer == "\x7f\x00\x00\x01")
						param.peerhost = '::1'
					else
						param.peerhost = '::ffff:' + Rex::Socket.getaddress(param.peerhost)
					end
				end
				
				param.v6 = true
			end	
		else
			# No IPv6 support
			param.v6 = false
		end
		
		# Notify handlers of the before socket create event.
		self.instance.notify_before_socket_create(self, param)

		# Create the socket
		sock = nil
		if (param.v6)
			sock = ::Socket.new(::Socket::AF_INET6, type, proto)		
		else
			sock = ::Socket.new(::Socket::AF_INET, type, proto)
		end

		# Bind to a given local address and/or port if they are supplied
		if (param.localhost || param.localport)
			begin	
				sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, true)

				sock.bind(Rex::Socket.to_sockaddr(param.localhost, param.localport))

			rescue Errno::EADDRINUSE
				sock.close
				raise Rex::AddressInUse.new(param.localhost, param.localport), caller
			end
		end
		
		# Configure broadcast support for all datagram sockets
		if (type == ::Socket::SOCK_DGRAM)
			sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BROADCAST, true)
		end

		# If a server TCP instance is being created...
		if (param.server?)
			sock.listen(32)

			if (param.bare? == false)
				klass = Rex::Socket::TcpServer
				if (param.ssl)
					klass = Rex::Socket::SslTcpServer
				end
				sock.extend(klass)

				sock.initsock(param)
			end
		# Otherwise, if we're creating a client...
		else
			chain = []

			# If we were supplied with host information
			if (param.peerhost)
				begin
					ip = param.peerhost
					port = param.peerport

					if param.proxies
						chain = param.proxies.dup
						chain.push(['host',param.peerhost,param.peerport])
						ip = chain[0][1]
						port = chain[0][2].to_i
					end

					begin
						timeout(param.timeout) do
						    sock.connect(Rex::Socket.to_sockaddr(ip, port))
						end
					rescue ::Timeout::Error
						raise ::Errno::ETIMEDOUT
					end						

				rescue ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
					sock.close
					raise Rex::HostUnreachable.new(param.peerhost, param.peerport), caller
				
				rescue Errno::ETIMEDOUT
					sock.close
					raise Rex::ConnectionTimeout.new(param.peerhost, param.peerport), caller
				
				rescue ::Errno::ECONNRESET,::Errno::ECONNREFUSED,::Errno::ENOTCONN,::Errno::ECONNABORTED
					sock.close
					raise Rex::ConnectionRefused.new(param.peerhost, param.peerport), caller
				end
			end

			if (param.bare? == false)
				case param.proto
					when 'tcp'
						klass = Rex::Socket::Tcp
						sock.extend(klass)
						sock.initsock(param)
					when 'udp'
						sock.extend(Rex::Socket::Udp)
						sock.initsock(param)
				end
			end

			if chain.size > 1
				chain.each_with_index {
					|proxy, i|
					next_hop = chain[i + 1]
					if next_hop
						proxy(sock, proxy[0], next_hop[1], next_hop[2])
					end
				}
			end
			
			# Now extend the socket with SSL and perform the handshake
			if(param.bare? == false and param.ssl)
				klass = Rex::Socket::SslTcp
				sock.extend(klass)
				sock.initsock(param)			
			end
			
			
		end

		# Notify handlers that a socket has been created.
		self.instance.notify_socket_created(self, sock, param)

		sock
	end
				
	def self.proxy(sock, type, host, port)
	
		#$stdout.print("PROXY\n")
		case type.downcase
		when 'http'
			setup = "CONNECT #{host}:#{port} HTTP/1.0\r\n\r\n"
			size = sock.put(setup)
			if (size != setup.length)
				raise ArgumentError, "Wrote less data than expected to the http proxy"
			end
			
			begin
				ret = sock.get_once(39,30)
			rescue IOError
				raise Rex::ConnectionRefused.new(host, port), caller
			end

			if ret.nil?
				raise ArgumentError, "The http proxy did not respond"
			end

			resp = Rex::Proto::Http::Response.new
			resp.update_cmd_parts(ret.split(/\r?\n/)[0])

			if resp.code != 200
				raise ArgumentError, "Connection with http proxy failed"
			end
		when 'socks4'
			setup = [4,1,port.to_i].pack('CCn') + Socket.gethostbyname(host)[3] + Rex::Text.rand_text_alpha(rand(8)+1) + "\x00"
			size = sock.put(setup)
			if (size != setup.length)
				raise ArgumentError, "Wrote less data than expected to the socks4 proxy"
			end

			begin
				ret = sock.get_once(8, 30)
			rescue IOError
				raise Rex::ConnectionRefused.new(host, port), caller
			end

			if (ret.nil? or ret.length < 8)
				raise ArgumentError, 'SOCKS4 server did not respond with a proper response'
			end
			if ret[1,1] != "\x5a"
				raise "SOCKS4 server responded with error code #{ret[0,1].unpack("C")[0]}"
			end
		when 'socks5'
			auth_methods = [5,1,0].pack('CCC')
			size = sock.put(auth_methods)
			if (size != auth_methods.length)
				raise ArgumentError, "Wrote less data than expected to the socks5 proxy"
			end
			ret = sock.get_once(2,30)
			if (ret[1,1] == "\xff")
				raise ArgumentError, "Proxy requires authentication"
			end

			if (Rex::Socket.is_ipv4?(host))
				addr = Rex::Socket.gethostbyname(host)[3] 
				setup = [5,1,0,1].pack('C4') + addr + [port.to_i].pack('n')
			elsif (Rex::Socket.support_ipv6? and Rex::Socket.is_ipv6?(host))
				# IPv6 stuff all untested
				addr = Rex::Socket.gethostbyname(host)[3] 
				setup = [5,1,0,4].pack('C4') + addr + [port.to_i].pack('n')
			else
				# Then it must be a domain name.
				# Unfortunately, it looks like the host has always been
				# resolved by the time it gets here, so this code never runs.
				setup = [5,1,0,3].pack('C4') + [host.length].pack('C') + host + [port.to_i].pack('n')
			end

			size = sock.put(setup)
			if (size != setup.length)
				raise ArgumentError, "Wrote less data than expected to the socks5 proxy"
			end

			begin
				response = sock.get_once(10, 30)
			rescue IOError
				raise Rex::ConnectionRefused.new(host, port), caller
			end

			if (response.nil? or response.length < 10)
				raise ArgumentError, 'SOCKS5 server did not respond with a proper response'
			end
			if response[1] != 0
				raise "SOCKS5 server responded with error code #{response[1]}"
			end
		else
			raise ArgumentError, 'Unsupported proxy type and/or version', caller
		end
	end

	##
	#
	# Registration
	#
	##
	
	def self.register_event_handler(handler) # :nodoc:
		self.instance.register_event_handler(handler)
	end

	def self.deregister_event_handler(handler) # :nodoc:
		self.instance.deregister_event_handler(handler)
	end

	def self.each_event_handler(handler) # :nodoc:
		self.instance.each_event_handler(handler)
	end

end
