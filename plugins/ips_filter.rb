module Msf

###
# 
# This class hooks all sockets created by a running exploit 
# and prevents data from being sent that matches a known IPS
# signature.
#
###

class Plugin::IPSFilter < Msf::Plugin

	###
	#
	# This class implements a socket communication logger
	#
	###
	class IPSSocketEventHandler
		include Rex::Socket::Comm::Events

		def on_before_socket_create(comm, param)
		end

		def on_socket_created(comm, sock, param)
			# Sockets created by the exploit have MsfExploit set and MsfPayload not set
			if (param.context['MsfExploit'] and (! param.context['MsfPayload'] ))
				sock.extend(IPSFilter::SocketTracer)
				sock.context = param.context
				sock._init_hook_
			end
		end		
	end
	

	def initialize(framework, opts)
		super
		@ips_eh = IPSSocketEventHandler.new
		Rex::Socket::Comm::Local.register_event_handler(@bps_eh)
	end

	def cleanup
		Rex::Socket::Comm::Local.deregister_event_handler(@bps_eh)
	end

	def name
		"ips_filter"
	end

	def desc
		"Scans all outgoing data to see if it matches a known IPS signature"
	end

protected
end

end

# This module extends the captured socket instance
module IPSFilter
module SocketTracer

	attr_accessor :context

	# Hook the write method
	def write(buf, opts = {})
		# Add hooks to filter all outgoing packets here
		super(buf)
	end

	# Hook the read method
	def read(length = nil, opts = {})
		r = super(length, opts)
		return r
	end

	# Called by the event handler on setup
	def _init_hook_
		# Load up the signature set here
	end

	def close(*args)
		super(*args)
	end

end
end
