module Msf

###
# 
# This class hooks all socket calls and updates the database with
# data gathered from the connection parameters
#
###

class Plugin::DB_Tracer < Msf::Plugin

	###
	#
	# This class implements a socket communication tracker
	#
	###
	class DBTracerEventHandler
		include Rex::Socket::Comm::Events

		def on_before_socket_create(comm, param)
		end

		def on_socket_created(comm, sock, param)
			# Ignore local listening sockets
			return if not sock.peerhost

			if (sock.peerhost != '0.0.0.0' and sock.peerport)

				# Ignore sockets that didn't set up their context 
				# to hold the framework in 'Msf'
				return if not param.context['Msf']

				host = param.context['Msf'].db.get_host(param.context, sock.peerhost)
				return if not host
				
				port = param.context['Msf'].db.get_service(param.context, host, param.proto, sock.peerport)
				return if not port

				if host.state != Msf::HostState::Alive
					param.context['Msf'].db.report_host_state(self, sock.peerhost, Msf::HostState::Alive)
				end
			end
		end		
	end
	
	def initialize(framework, opts)
		super
		
		if(not framework.db.active)
			raise PluginLoadError.new("The database backend has not been initialized")
		end
		
		@eh = DBTracerEventHandler.new
		Rex::Socket::Comm::Local.register_event_handler(@eh)
	end

	def cleanup
		Rex::Socket::Comm::Local.deregister_event_handler(@eh)
	end

	def name
		"db_tracker"
	end

	def desc
		"Monitors socket calls and updates the database backend"
	end

end
end
