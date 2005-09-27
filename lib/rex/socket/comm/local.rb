require 'rex/exceptions'
require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/socket/ssl_tcp'
require 'rex/socket/udp'

###
#
# Local
# -----
#
# Local communication class factory.
#
###
class Rex::Socket::Comm::Local

	#
	# Creates an instance of a socket using the supplied parameters.
	#
	def self.create(param)
		case param.proto
			when 'tcp'
				return create_by_type(param, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_TCP)
			when 'udp'
				return create_by_type(param, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)
			else
				raise Rex::UnsupportedProtocol.new(param.proto), caller
		end
	end

	#
	# Creates a socket 
	#
	def self.create_by_type(param, type, proto = 0)
		# Create the socket
		sock = ::Socket.new(::Socket::AF_INET, type, proto)

		# Bind to a given local address and/or port if they are supplied
		if (param.localhost || param.localport)
			begin	
				if (param.server?)
					sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
				end

				sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)

				sock.bind(Rex::Socket.to_sockaddr(param.localhost, param.localport))
			rescue Errno::EADDRINUSE
				raise Rex::AddressInUse.new(param.localhost, param.localport), caller
			end
		end

		# If a server TCP instance is being created...
		if (param.server?)
			sock.listen(32)

			return sock if (param.bare?)

			sock.extend(Rex::Socket::TcpServer)

			sock.initsock(param)

			return sock
		# Otherwise, if we're creating a client...
		else
			# If we were supplied with host information
			if (param.peerhost)
				begin
					sock.connect(Rex::Socket.to_sockaddr(param.peerhost, param.peerport))
				rescue Errno::ECONNREFUSED
					raise Rex::ConnectionRefused.new(param.peerhost, param.peerport), caller
				end
			end

			return sock if (param.bare?)

			case param.proto
				when 'tcp'
					klass = Rex::Socket::Tcp

					if (param.ssl)
						klass = Rex::Socket::SslTcp
					end

					sock.extend(klass)

					sock.initsock(param)

					return sock
				when 'udp'
					sock.extend(Rex::Socket::Udp)

					sock.initsock(param)

					return sock
			end
		end
	end

end
