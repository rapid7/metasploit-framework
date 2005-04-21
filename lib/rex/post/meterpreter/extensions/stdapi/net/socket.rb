#!/usr/bin/ruby

require 'thread'
require 'Rex/Socket/Stream'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Tlv'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Net/SocketSubsystem/TcpClientChannel'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# Socket
# ------
#
# This class provides an interface to interacting with sockets
# on the remote machine.  It allows callers to open TCP, UDP,
# and other arbitrary socket-based connections as channels that
# can then be interacted with through the established 
# meterpreter connection.
#
###
class Socket

	##
	#
	# Constructor
	#
	##

	# Initialize the socket subsystem and start monitoring sockets
	# as they come in
	def initialize(client)
		self.client                    = client
		self.monitored_sockets         = []
		self.monitored_socket_channels = {}

		# Start monitoring shit like the business
		self.monitor_sockets
	end

	# Terminate the monitor thread
	def shutdown
		monitor_thread.kill
	end

	##
	#
	# Factory
	#
	##

	# Creates an arbitrary client socket channel using the information
	# supplied in the socket parameters instance.  The 'params' argument
	# is expected to be of type Rex::Socket::Parameters
	def create(params)
		channel = nil
		res     = nil

	#	begin
			if (params.tcp?)
				if (params.server?)
					channel = create_tcp_server(params)
				else
					channel = create_tcp_client(params)
				end

				# Add this channel's right socket to the socket monitor
				add_monitored_socket(channel.rsock, channel)

				# If we get a valid channel back, create a stream 
				# representation of the left side of the socket for
				# the caller to use
				if (channel != nil)
					res = Rex::Socket::Stream.new(channel.lsock, nil, nil, nil)
				end
			elsif (params.udp?)
				if (params.server?)
					res = create_udp_server(params)
				else
					res = create_udp_client(params)
				end

				# TODO: Datagram wrapper
			end
	#	rescue
	#	end

		return res
	end

	# Create a TCP server channel
	def create_tcp_server(params)
	end

	# Creates a TCP client channel
	def create_tcp_client(params)
		return SocketSubsystem::TcpClientChannel.open(client, params)
	end

	# Creates a UDP server channel
	def create_udp_server(params)
	end

	# Creates a UDP client channel
	def create_udp_client(params)
	end

protected

	##
	#
	# Socket monitoring
	#
	##

	# Monitors zero or more sockets and handles forwarding traffic
	# to the remote half of the associated channel
	def monitor_sockets
		self.monitor_thread = ::Thread.new {

			while (1)
		
				# Watch for data
				socks = select(monitored_sockets, nil, nil, 1)

				# No data?
				if (socks == nil || socks[0] == nil)
					next
				end

				# Enumerate through each of the indicated sockets
				socks[0].each { |sock|
					channel = monitored_socket_channels[sock.object_id]
					closed  = false
					data    = nil

					if (channel == nil)
						remove_monitored_socket(sock)

						next
					end

					begin
						data = sock.sysread(16384)
					rescue
						closed = true
					end

					if (data == nil)
						closed = true
					end

					# If the socket closed, notify the other side and remove
					# this socket from the monitored socket list
					if (closed)
						channel.close

						remove_monitored_socket(sock)
					# Otherwise, write the data to the remote side
					else
						channel.write(data)
					end
				}

			end

		}
	end

	# Adds a socket to the list of monitored sockets
	def add_monitored_socket(sock, channel)
		monitored_sockets << sock
		monitored_socket_channels[sock.object_id] = channel
	end

	# Removes a socket from the list of monitored sockets
	def remove_monitored_socket(sock)
		monitored_socket_channels.delete(sock.object_id)
		monitored_sockets.delete(sock)
	end

	attr_accessor :monitored_sockets, :monitored_socket_channels
	attr_accessor :monitor_thread
	attr_accessor :client

end

end; end; end; end; end; end
