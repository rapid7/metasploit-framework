module Msf
module Handler

###
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

	#
	# Returns the handler specific string representation, in this case
	# 'bind_tcp'.
	#
	def self.handler_type
		return "bind_tcp"
	end

	#
	# Returns the connection oriented general handler type, in this case bind.
	#
	def self.general_handler_type
		"bind"
	end

	#
	# Initializes a bind handler and adds the options common to all bind
	# payloads, such as local port.
	#
	def initialize(info = {})
		super

		register_options(
			[
				Opt::LPORT(4444)
			], Msf::Handler::BindTcp)

		self.conn_threads = []
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

		# Maximum number of seconds to run the handler
		ctimeout = 300
		
		if (exploit_config and exploit_config['active_timeout'])
			ctimeout = exploit_config['active_timeout'].to_i
		end
	
		self.listener_thread = Thread.new {
			client = nil

			print_status("Started bind handler")

			if (datastore['RHOST'] == nil)
				raise ArgumentError, 
					"RHOST is not defined; bind stager cannot function.",
					caller
			end

			stime = Time.now.to_i
			
			while (stime + ctimeout > Time.now.to_i)
				begin
					client = Rex::Socket::Tcp.create(
						'PeerHost' => datastore['RHOST'],
						'PeerPort' => datastore['LPORT'].to_i,
						'Proxies'  => datastore['Proxies'],
						'Comm'     => comm,
						'Context'  =>
							{
								'Msf'        => framework,
								'MsfPayload' => self,
								'MsfExploit' => assoc_exploit
							})
				rescue Rex::ConnectionRefused
					# Connection refused is a-okay
				rescue ::Exception
					wlog("Exception caught in bind handler: #{$!}")
				end

				break if client

				# Wait a second before trying again
				Rex::ThreadSafe.sleep(0.5)
			end
			
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
			else
				wlog("No connection received before the handler completed")
			end
		}
	end

	# 
	# Nothing to speak of.
	#
	def stop_handler
		# Stop the listener thread.
		if (listener_thread)
			listener_thread.kill
			self.listener_thread = nil
		end
	end

protected

	attr_accessor :conn_threads # :nodoc:
	attr_accessor :listener_thread # :nodoc:

end

end
end
