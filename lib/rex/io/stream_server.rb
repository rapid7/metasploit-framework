module Rex
module IO

###
#
# StreamServer
# ------------
#
# This mixin provides the framework and interface for implementing a streaming
# server that can listen for and accept stream client connections.
#
###
module StreamServer

	##
	#
	# Abstract methods
	#
	##

	#
	# Accepts an incoming stream connection and returns an instance of a
	# Stream-drived class.
	#
	def accept(opts = {})
		super
	end

	#
	# Polls to see if a client connection is pending
	#
	def pending_client?(timeout = nil)
		super
	end

	#
	# Returns the file descriptor that can be polled via select
	#
	def poll_fd
		super
	end

	##
	#
	# Default server monitoring and client management implementation follows
	# below.
	#
	##

	def on_client_connect(client)
		if (on_client_connect_proc)
			on_client_connect_proc.call(client)
		end
	end

	def on_client_data(client)
		if (on_client_data_proc)
			on_client_data_proc.call(client)
		end
	end

	def on_client_close(client)
		if (on_client_close_proc)
			on_client_close_proc.call(client)
		end
	end

	#
	# Start monitoring the listener socket for connections and keep track of
	# all client connections.
	#
	def start
		self.clients = []
		self.clifds  = []
		self.fd2cli  = {}

		self.listener_thread = Thread.new {
			monitor_listener
		}
		self.clients_thread = Thread.new {
			monitor_clients
		}
	end

	#
	# Terminates the listener monitoring threads and closes all active clients.
	#
	def stop
		self.listener_thread.kill
		self.clients_thread.kill

		self.clients.each { |cli|
			close_client(cli)
		}
	end

	#
	# Closes a client connection.
	#
	def close_client(client)
		if (client)
			fd2cli.delete(client.sock)
			clifds.delete(client.sock)
			clients.delete(client)

			client.close
		end
	end

	#
	# Callback procedures.
	#
	attr_accessor :on_client_connect_proc
	attr_accessor :on_client_data_proc
	attr_accessor :on_client_close_proc

protected

	attr_accessor :clients, :clifds, :fd2cli
	attr_accessor :listener_thread, :clients_thread

	#
	# Monitors the listener socket for new connections
	#
	def monitor_listener
		begin
			sd = Rex::ThreadSafe.select([ poll_fd ])

			# Accept the new client connection
			if (sd[0].length > 0)
				cli = accept

				next if (!cli)

				# Insert it into some lists
				self.clients << cli
				self.clifds  << cli.sock
				self.fd2cli[cli.sock] = cli

				on_client_connect(cli)
			end
		rescue SyntaxError
			elog("Syntax error in stream server listener monitor: #{$!}")
			rlog(ExceptionCallStack)
		rescue
			elog("Error in stream server listener monitor: #{$!}")
		end while true

	end

	#
	# Monitors clients for data.
	#
	def monitor_clients
		begin
			if (clients.length == 0)
				Rex::ThreadSafe::sleep(0.2)
				next
			end

			sd = Rex::ThreadSafe.select(clifds)

			sd[0].each { |fd|
				on_client_data(self.fd2cli[fd])
			}
		rescue SyntaxError
			elog("Syntax error in stream server listener monitor: #{$!}")
			rlog(ExceptionCallStack)
		rescue
			elog("Error in stream server client monitor: #{$!}")
		end while true
	end

end

end 
end
