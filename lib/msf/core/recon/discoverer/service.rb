module Msf
class  Recon
class  Discoverer

###
#
# This class provides a base class for all recon modules that attempt to
# discover the presence of a service on a host.
#
###
class Service < Msf::Recon::Discoverer

	def initialize(info = {})
		super

		# Register the options that this particular discovery module uses
		register_options(
			[
				Opt::RHOST
			], Msf::Recon::Discoverer::Service)
	end

	#
	# This method returns that this is a service discoverer recon module.
	#
	def discoverer_type
		Type::Service
	end

	#
	# By default, service discoverer recon modules do no support
	# multi-threading.
	#
	def discoverer_flags
		0
	end

	#
	# Probes a host entity to see what services it has open.  Extended modules
	# should report service state changes directly via the report_service_state
	# instance method.
	#
	def probe_host(host)
	end

protected

	#
	# Wraps the probing of a host.
	#
	def discovery_thread
		if ((host = framework.reconmgr.get_host(datastore['RHOST'])) == nil)
			host = Msf::Recon::Entity::Host.new(datastore['RHOST'])
		end

		probe_host(host)
	end

	#
	# This method reports the state of a service to the recon manager so that
	# it can be tracked appropriately.
	#
	def report_service_state(host, proto, port, istate)
		state   = istate
		context = nil

		# If the state passed in as an argument is a hash, then create an event
		# context that we'll pass along to the recon manager in case other
		# subscribers might be able to make use of it.
		if (istate.kind_of?(Hash))
			context = Msf::Recon::EventContext.new

			context.from_hash(istate)

			state = istate['state']
		end

		# Log that we detected an up service
		if (state == ServiceState::Up)
			dlog("Found port #{port} (#{proto}) open on #{host.address}.", "core",
				LEV_2)
		end

		# Pass the normalized service state notifications to the recon manager.
		framework.reconmgr.report_service_state(self, host, proto, port, 
			state, context)
	end

end

end
end
end
