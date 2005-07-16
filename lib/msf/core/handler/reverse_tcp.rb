module Msf
module Handler

###
#
# ReverseTcp
# ----------
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

	def self.handler_type
		return "reverse_tcp"
	end

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
	# if it fails to start the listener
	#
	def setup_handler
		self.listener_sock = Rex::Socket::TcpServer.create(
			'LocalHost' => datastore['LHOST'],
			'LocalPort' => datastore['LPORT'].to_i,
			'Comm'      => comm)
	end

	#
	# Closes the listener socket if one was created
	#
	def cleanup_handler
		if (self.listener_sock)
			self.listener_sock.close
			self.listener_sock = nil
		end

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
		listener_thread = Thread.new {
			client = nil
			# Accept a client connection
			begin
				client = self.listener_sock.accept	
			rescue
				wlog("Exception raised during listener accept: #{$!}")
				return nil
			end
			
			# Start a new thread and pass the client connection
			# as the input and output pipe.  Client's are expected
			# to implement the Stream interface.
			conn_threads << Thread.new {
				begin
					handle_connection(client)
				rescue
					elog("Exception raised from handle_connection: #{$!}")
				end
			}
		}
	end

	# 
	# Stops monitoring for an inbound connection
	#
	def stop_handler
		# Terminate the listener thread
		if (self.listener_thread and self.listener_thread.alive? == true)
			self.listener_thread.kill
			self.listener_thread = nil
		end
	end

protected

	attr_accessor :listener_sock
	attr_accessor :listener_thread
	attr_accessor :conn_threads

end

end
end
