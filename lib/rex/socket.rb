require 'socket'
require 'resolv'

module Rex

###
#
# Socket
# ------
#
# Base class for all sockets.
#
###
class Socket

	module Comm
	end

	require 'Rex/Socket/Parameters'

	##
	#
	# Factory methods
	#
	##

	def self.create(opts)
		return create_param(Rex::Socket::Parameters.from_hash(opts))
	end

	def self.create_param(param)
		return param.comm.create(param)
	end

	def self.create_tcp(opts)
		return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'tcp')))
	end
	
	def self.create_tcp_server(opts)
		return create_tcp(opts.merge('Server' => true))
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

	##
	#
	# Class initialization
	#
	##
	
	def initialize(sock, params = nil)
		self.sock = sock

		if (params)
			self.peerhost  = params.peerhost
			self.peerport  = params.peerport
			self.localhost = params.localhost
			self.localport = params.localport
		end
	end

	#
	# Closes the associated socket
	#
	def close
		self.sock.close if (self.sock)
	end

	#
	# Returns the sock context that was supplied to the constructor as the
	# default poll_fd
	#
	def poll_fd
		return self.sock
	end

	attr_reader :sock
	attr_reader :peerhost, :peerport, :localhost, :localport

protected

	attr_writer :sock
	attr_writer :peerhost, :peerport, :localhost, :localport

end

end
