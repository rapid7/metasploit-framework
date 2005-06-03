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
	
	def initialize(sock)
		self.sock = sock
	end

	attr_reader :sock

protected

	attr_writer :sock

end

end
