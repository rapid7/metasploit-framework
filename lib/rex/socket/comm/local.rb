require 'singleton'
require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/socket/ssl_tcp'
require 'rex/socket/udp'

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
			else
				raise Rex::UnsupportedProtocol.new(param.proto), caller
		end
	end

	#
	# Creates a socket using the supplied Parameter instance.
	#
	def self.create_by_type(param, type, proto = 0)
		# Notify handlers of the before socket create event.
		self.instance.notify_before_socket_create(self, param)

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

			if (param.bare? == false)
				case param.proto
					when 'tcp'
						klass = Rex::Socket::Tcp
	
						if (param.ssl)
							klass = Rex::Socket::SslTcp
						end
	
						sock.extend(klass)
	
						sock.initsock(param)
					when 'udp'
						sock.extend(Rex::Socket::Udp)
	
						sock.initsock(param)
				end
			end
		end

		# Notify handlers that a socket has been created.
		self.instance.notify_socket_created(self, sock, param)

		sock
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
