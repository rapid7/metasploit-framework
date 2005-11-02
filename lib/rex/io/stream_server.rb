module Rex
module IO

###
#
# This mixin provides the framework and interface for implementing a streaming
# server that can listen for and accept stream client connections.  Stream
# servers extend this class and are required to implement the following
# methods:
#
#   accept
#   fd
#
###
module StreamServer

	##
	#
	# Abstract methods
	#
	##

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

	attr_accessor :clients
	attr_accessor :listener_thread, :clients_thread

	#
	# Monitors the listener socket for new connections
	#
	def monitor_listener
		begin
			sd = Kernel.select([ fd ])

			# Accept the new client connection
			if (sd[0].length > 0)
				cli = accept

				next unless cli

				# Insert it into some lists
				self.clients << cli

				on_client_connect(cli)
			end
		rescue
			elog("Error in stream server listener monitor: #{$!}")
			rlog(ExceptionCallStack)
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

			sd = Rex::ThreadSafe.select(clients)

			sd[0].each { |fd|
				on_client_data(fd)
			}
		rescue
			elog("Error in stream server client monitor: #{$!}")
			rlog(ExceptionCallStack)
		end while true
	end

end

end 
end
