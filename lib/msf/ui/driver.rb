module Msf
module Ui

###
#
# Driver
# ------
#
# The driver class is an abstract base class that is meant to provide
# a very general set of methods for 'driving' a user interface.
#
###
class Driver

	def initialize
		self.datastore = DataStore.new
	end

	# Executes the user interface, optionally in an asynchronous fashion
	def run
		raise NotImplementedError
	end

	# Stops executing the user interface
	def stop
	end

	# Cleans up any resources associated with the UI driver
	def cleanup
	end

	#
	# Arbitrary state storage
	#

	# Store a keyed value
	def store(key, value)
		datastore[key] = value
	end

	# Retrieve a keyed value
	def fetch(key)
		return datastore[key]
	end

	attr_reader :datastore

protected

	attr_writer :datastore

end

end
end
