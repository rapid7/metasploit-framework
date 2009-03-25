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

	#
	# This callback is notified when a client connects.
	#
	def on_client_connect(client)
		if (on_client_connect_proc)
			on_client_connect_proc.call(client)
		end
	end

	#
	# This callback is notified when a client connection has data that needs to
	# be processed.
	#
	def on_client_data(client)
		if (on_client_data_proc)
			on_client_data_proc.call(client)
		end
	end

	#
	# This callback is notified when a client connection has closed.
	#
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
	# This method closes a client connection and cleans up the resources
	# associated with it.
	#
	def close_client(client)
		if (client)
			clients.delete(client)

			begin
				client.close
			rescue IOError
			end
		end
	end
	
	#
	# This method waits on the server listener thread
	#
	def wait
		self.listener_thread.join if self.listener_thread
	end	

	##
	#
	# Callback procedures.
	#
	##
	
	#
	# This callback procedure can be set and will be called when new clients
	# connect.
	#
	attr_accessor :on_client_connect_proc
	#
	# This callback procedure can be set and will be called when clients
	# have data to be processed.
	#
	attr_accessor :on_client_data_proc
	#
	# This callback procedure can be set and will be called when a client
	# disconnects from the server.
	#
	attr_accessor :on_client_close_proc

protected

	attr_accessor :clients # :nodoc:
	attr_accessor :listener_thread, :clients_thread # :nodoc:

	#
	# This method monitors the listener socket for new connections and calls
	# the +on_client_connect+ callback routine.
	#
	def monitor_listener
	
		begin
			sd = Kernel.select([ fd ], nil, nil, 0.25)

			# Accept the new client connection
			if (sd and sd[0].length > 0)
				begin
					cli = accept

					next unless cli

					# Insert it into some lists
					self.clients << cli

					on_client_connect(cli)
					
				# Skip exceptions caused by accept() [ SSL ]
				rescue ::EOFError, ::Errno::ECONNRESET, ::Errno::ENOTCONN, ::Errno::ECONNABORTED
				end
			end

		rescue ::Exception
			elog("Error (#{$!.class}) in stream server listener monitor:  #{$!}")
			rlog($!.backtrace)
			break
		end while true

	end

	#
	# This method monitors client connections for data and calls the
	# +on_client_data+ routine when new data arrives.
	#
	def monitor_clients
		begin
			if (clients.length == 0)
				Rex::ThreadSafe::sleep(0.25)
				next
			end

			sd = Rex::ThreadSafe.select(clients)

			sd[0].each { |fd|
				begin
					on_client_data(fd)
				rescue ::EOFError, ::Errno::ECONNRESET, ::Errno::ENOTCONN, ::Errno::ECONNABORTED
					on_client_close(fd)
					close_client(fd)
				rescue ::Interrupt
					raise $!					
				rescue ::Exception
					close_client(fd)
					elog("Error in stream server client monitor: #{$!}")
					rlog(ExceptionCallStack)
					
				end
			}
			
		rescue ::Rex::StreamClosedError => e
			# Remove the closed stream from the list
			clients.delete(e.stream)
		rescue ::Interrupt
			raise $!
		rescue ::Exception
			elog("Error in stream server client monitor: #{$!}")
			rlog(ExceptionCallStack)		
		end while true
	end

end

end 
end
