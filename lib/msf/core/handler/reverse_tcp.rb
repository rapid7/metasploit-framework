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

	def initialize(info = {})
		super

		register_options(
			[
				Opt::LHOST("0.0.0.0"),
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
		listener_sock = comm.create(
			'LocalHost' => datastore['LHOST'] || "0.0.0.0",
			'LocalPort' => datastore['LPORT'].to_i,
			'Server'    => true,
			'Proto'     => 'tcp')
	end

	#
	# Closes the listener socket if one was created
	#
	def cleanup_handler
		if (listener_sock)
			listener_sock.close
			listener_sock = nil
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
			# Accept a client connection
			begin
				client = listener_sock.accept	
			rescue
				wlog("Exception raised during listener accept: #{$!}"
			end

			# Start a new thread and pass the client connection
			# as the input and output pipe
			conn_threads << Thread.new {
				handle_connection(client, client)
			}
		}
	end

	# 
	# Stops monitoring for an inbound connection
	#
	def stop_handler
		# Terminate the listener thread
		if (listener_thread and listener_thread.alive? == true)
			listener_thread.kill
			listener_thread = nil
		end
	end

protected

	attr_accessor :listener_sock
	attr_accessor :listener_thread
	attr_accessor :conn_threads

end

end
end
