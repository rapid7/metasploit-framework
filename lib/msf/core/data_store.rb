module Msf

###
#
# DataStore
# ---------
#
# The data store is just a bitbucket that holds keyed values.
#
###
class DataStore < Hash

	# This method is a helper method that imports the default value for
	# all of the supplied options
	def import_options(options)
		options.each_option { |name, opt|
			if (opt.default_value)
				self.store(name, opt.default_value)
			end
		}
	end
end

end
