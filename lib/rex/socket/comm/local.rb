require 'Rex/Socket'
require 'Rex/Socket/Tcp'
require 'Rex/Socket/SslTcp'
require 'Rex/Socket/Udp'

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

				sock.bind(Rex::Socket.to_sockaddr(param.localhost, param.localport))
			rescue Errno::EADDRINUSE
				raise Rex::AddressInUse.new(param.localhost, param.localport), caller
			end
		end

		# If a server TCP instance is being created...
		if (param.server?)
			sock.listen(32)

			return sock if (param.bare?)

			return Rex::Socket::TcpServer.new(sock, param)
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

					return klass.new(sock, param)
				when 'udp'
					return Rex::Socket::Udp.new(sock, param)
			end
		end
	end

end
