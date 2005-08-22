require 'singleton'
require 'rex'
require 'rex/service'

module Rex

###
#
# ServiceManager
# --------------
#
# This class manages service allocation and interaction.  This class can be
# used to start HTTP servers and manage them and all that stuff.  Yup.
#
###
class ServiceManager < Hash

	#
	# This class is a singleton.
	#
	include Singleton

	#
	# Calls the instance method to start a service.
	#
	def self.start(klass, *args)
		self.instance.start(klass, *args)
	end
	
	#
	# Calls the instance method to stop a service.
	#
	def self.stop(als)
		self.instance.stop(als)
	end

	#
	# Starts a service and assigns it a unique name in the service hash.
	#
	def start(klass, *args)
		# Get the hardcore alias.
		hals = "__#{klass.name}#{args.to_s}"

		# Has a service already been constructed for this guy?  If so, increment
		# its reference count like it aint no thang.
		if (inst = self[hals])
			inst.ref
			return inst
		end

		inst = klass.new(*args)
		als  = inst.alias

		# Find an alias that isn't taken.
		if (self[als])
			cnt  = 1
			cnt += 1 while (self[als + " #{cnt}"])
			als += " #{cnt}"
		end

		# Extend the instance as a service.
		inst.extend(Rex::Service)

		# Re-aliases the instance.
		inst.alias = als

		# Fire up the engines.  If an error occurs an exception will be 
		# raised.
		inst.start

		# Alias associate and initialize reference counting
		self[als] = self[hals] = inst.refinit
	end

	#
	# Stops a service using the provided alias
	#
	def stop(als)
		# Stop the service and be done wif it, but only if the number of
		# references has dropped to zero
		if ((inst = self[als]) and
		    (inst.deref))
			inst.stop

			# Since the instance may have multiple aliases, scan through
			# all the pairs for matching stuff.
			self.each_pair { |cals, cinst|
				self.delete(cals) if (inst == cinst)
			}
		end
	end
	
end

end
