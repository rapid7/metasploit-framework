require 'msf/base'

module Msf
module Simple

###
#
# Module
# ------
#
# Simple module wrapper that provides some common methods for dealing with
# modules, such as importing options and other such things.
#
###
module Module

	#
	# Imports extra options from the supplied hash either as a string or as a
	# hash.
	#
	def _import_extra_options(opts)
		# If options were supplied, import them into the payload's
		# datastore
		if (opts['Option'])
			self.datastore.import_options_from_hash(opts['Options'])
		elsif (opts['OptionStr'])
			self.datastore.import_options_from_s(opts['OptionStr'])
		end
	end

end

end
end
