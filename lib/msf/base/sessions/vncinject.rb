require 'msf/base'
require 'rex/services/local_relay'

module Msf
module Sessions

###
#
#
###
class VncInject 

	#
	# The vncinject session is interactive
	#
	include Msf::Session
	include Msf::Session::Interactive

	#
	# Initializes a vncinject session instance using the supplied rstream
	# that is to be used as the client's connection to the server.
	#
	def initialize(rstream)
		super

		self.conn_eof = false
		self.got_conn = false
	end

	#
	# Cleans up the local relay and closes the stream.
	#
	def cleanup
		# Stop the local TCP relay
		service = Rex::ServiceManager.start(Rex::Services::LocalRelay)

		if (service)
			begin
				service.stop_tcp_relay(vlport, vlhost) if (vlport)
			ensure
				service.deref
			end
		end

		super
	end

	#
	# Returns the session type as being 'vncinject'.
	#
	def self.type
		"vncinject"
	end

	##
	#
	# Msf::Session overrides
	#
	##

	#
	# Returns the session description.
	#
	def desc
		"VNC Server"
	end

	#
	# Calls the class method.
	#
	def type
		self.class.type
	end

	def _interact
		raise EOFError if (self.conn_eof == true)

		sleep(1)
	end

	##
	#
	# VNC Server specific interfaces
	#
	##

	#
	# Sets up a local relay that is associated with the stream connection
	#
	def setup_relay(port, host = '127.0.0.1')
		if (port)
			self.vlhost = host
			self.vlport = port

			service = Rex::ServiceManager.start(Rex::Services::LocalRelay)

			if (service)
				begin
					service.start_tcp_relay(port,
						'LocalHost'         => host,
						'Stream'            => true,
						'OnLocalConnection' => Proc.new {
							if (self.got_conn == true)
								nil
							else
								self.got_conn = true

								rstream
							end
						},
						'OnConnectionClose' => Proc.new {
							if (self.conn_eof == false)	
								print_status("VNC connection closed.")
								self.conn_eof = true
							end
						},
						'__RelayType'       => 'vncinject')
				ensure
					service.deref
				end
			else
				raise RuntimeError, "Relay failed to start."
			end
		end
	end

	#
	# Launches VNC viewer against the local relay for this VNC server session.
	#
	def autovnc
		if (Rex::FileUtils::find_full_path('vncviewer'))
			Thread.new {
				system("vncviewer #{vlhost}::#{vlport}")
			}
		end
	end

protected

	attr_accessor :vlhost    # :nodoc:
	attr_accessor :vlport    # :nodoc:
	attr_accessor :conn_eof  # :nodoc:
	attr_accessor :got_conn  # :nodoc:

end

end
end
