module Msf
module Handler

###
#
# BindTcp
# -------
#
# This module implements the Bind TCP handler.  This means that
# it will attempt to connect to a remote host on a given port for a period of
# time (typically the duration of an exploit) to see if a the payload has
# started listening.  This can tend to be rather verbose in terms of traffic
# and in general it is preferable to use reverse payloads.
#
###
module BindTcp

	include Msf::Handler

	def self.handler_type
		return "bind_tcp"
	end

	def initialize(info = {})
		super

		register_options(
			[
				Opt::RHOST,
				Opt::LPORT(4444)
			], Msf::Handler::BindTcp)

		self.conn_threads = []
	end

	#
	# No setup to speak of
	#
	def setup_handler
	end

	#
	# Kills off the connection threads if there are any hanging around.
	#
	def cleanup_handler
		# Kill any remaining handle_connection threads that might
		# be hanging around
		conn_threads.each { |thr|
			thr.kill
		}
	end

	#
	# Starts monitoring for an outbound connection to become established.
	#
	def start_handler
		listener_thread = Thread.new {
			client = nil

			print_status("Started bind handler")

			# Keep trying to connect
			callcc { |ctx|
				while true
					begin
						client = Rex::Socket::Tcp.create(
							'PeerHost' => datastore['RHOST'],
							'PeerPort' => datastore['LPORT'].to_i,
							'Comm'     => comm)
					rescue Rex::ConnectionRefused
						# Connection refused is a-okay
					rescue
						wlog("Exception caught in bind handler: #{$!}")
					end
	
					ctx.call if (client)	
	
					# Wait a second before trying again
					Rex::ThreadSafe.sleep(0.5)
				end
			}

			# Valid client connection?
			if (client)
				# Start a new thread and pass the client connection
				# as the input and output pipe.  Client's are expected
				# to implement the Stream interface.
				conn_threads << Thread.new {
					begin
						handle_connection(client)
					rescue
						elog("Exception raised from BindTcp.handle_connection: #{$!}")
					end
				}
			end
		}
	end

	# 
	# Nothing to speak of.
	#
	def stop_handler
	end

protected

	attr_accessor :conn_threads

end

end
end
