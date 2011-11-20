require 'rex/socket'
require 'thread'

module Msf
module Handler

###
#
# This module implements the reverse TCP handler.  This means
# that it listens on a port waiting for a connection until
# either one is established or it is told to abort.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseTcp

	include Msf::Handler

	#
	# Returns the string representation of the handler type, in this case
	# 'reverse_tcp'.
	#
	def self.handler_type
		return "reverse_tcp"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'reverse'.
	#
	def self.general_handler_type
		"reverse"
	end

	#
	# Initializes the reverse TCP handler and ads the options that are required
	# for all reverse TCP payloads, like local host and local port.
	#
	def initialize(info = {})
		super

		register_options(
			[
				Opt::LHOST,
				Opt::LPORT(4444)
			], Msf::Handler::ReverseTcp)

		# XXX: Not supported by all modules
		register_advanced_options(
			[
				OptInt.new('ReverseConnectRetries', [ true, 'The number of connection attempts to try before exiting the process', 5 ]),
				OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
				OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
			], Msf::Handler::ReverseTcp)


		self.handler_queue = ::Queue.new
	end

	#
	# Starts the listener but does not actually attempt
	# to accept a connection.  Throws socket exceptions
	# if it fails to start the listener.
	#
	def setup_handler
		if datastore['Proxies']
			raise RuntimeError, 'TCP connect-back payloads cannot be used with Proxies'
		end

		ex = false
		# Switch to IPv6 ANY address if the LHOST is also IPv6
		addr = Rex::Socket.resolv_nbo(datastore['LHOST'])
		# First attempt to bind LHOST. If that fails, the user probably has
		# something else listening on that interface. Try again with ANY_ADDR.
		any = (addr.length == 4) ? "0.0.0.0" : "::0"

		addrs = [ Rex::Socket.addr_ntoa(addr), any  ]

		comm  = datastore['ReverseListenerComm']
		if comm.to_s == "local"
			comm = ::Rex::Socket::Comm::Local
		else
			comm = nil
		end

		if not datastore['ReverseListenerBindAddress'].to_s.empty?
			# Only try to bind to this specific interface
			addrs = [ datastore['ReverseListenerBindAddress'] ]

			# Pick the right "any" address if either wildcard is used
			addrs[0] = any if (addrs[0] == "0.0.0.0" or addrs == "::0")
		end
		addrs.each { |ip|
			begin

				self.listener_sock = Rex::Socket::TcpServer.create(
					'LocalHost' => ip,
					'LocalPort' => datastore['LPORT'].to_i,
					'Comm'      => comm,
					'Context'   =>
						{
							'Msf'        => framework,
							'MsfPayload' => self,
							'MsfExploit' => assoc_exploit
						})

				ex = false

				comm_used = comm || Rex::Socket::SwitchBoard.best_comm( ip )
				comm_used = Rex::Socket::Comm::Local if comm_used == nil

				if( comm_used.respond_to?( :type ) and comm_used.respond_to?( :sid ) )
					via = "via the #{comm_used.type} on session #{comm_used.sid}"
				else
					via = ""
				end

				print_status("Started reverse handler on #{ip}:#{datastore['LPORT']} #{via}")
				break
			rescue
				ex = $!
				print_error("Handler failed to bind to #{ip}:#{datastore['LPORT']}")
			end
		}
		raise ex if (ex)
	end

	#
	# Closes the listener socket if one was created.
	#
	def cleanup_handler
		stop_handler
	end

	#
	# Starts monitoring for an inbound connection.
	#
	def start_handler
		self.listener_thread = framework.threads.spawn("ReverseTcpHandlerListener-#{datastore['LPORT']}", false) {
			client = nil

			begin
				# Accept a client connection
				begin
					client = self.listener_sock.accept
				rescue
					wlog("Exception raised during listener accept: #{$!}\n\n#{$@.join("\n")}")
					break
				end

				# Increment the has connection counter
				self.pending_connections += 1

				self.handler_queue.push( client )
			end while true
		}

		self.handler_thread = framework.threads.spawn("ReverseTcpHandlerWorker-#{datastore['LPORT']}", false) {
			while true
				client = self.handler_queue.pop
				begin
					handle_connection(client)
				rescue ::Exception
					elog("Exception raised from handle_connection: #{$!.class}: #{$!}\n\n#{$@.join("\n")}")
				end
			end
		}

	end

	#
	# Stops monitoring for an inbound connection.
	#
	def stop_handler
		# Terminate the listener thread
		if (self.listener_thread and self.listener_thread.alive? == true)
			self.listener_thread.kill
			self.listener_thread = nil
		end

		# Terminate the handler thread
		if (self.handler_thread and self.handler_thread.alive? == true)
			self.handler_thread.kill
			self.handler_thread = nil
		end

		if (self.listener_sock)
			self.listener_sock.close
			self.listener_sock = nil
		end
	end

protected

	attr_accessor :listener_sock # :nodoc:
	attr_accessor :listener_thread # :nodoc:
	attr_accessor :handler_thread # :nodoc:
	attr_accessor :handler_queue # :nodoc:
end

end
end
