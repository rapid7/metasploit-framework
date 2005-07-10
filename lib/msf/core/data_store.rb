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

	#
	# This method is a helper method that imports the default value for
	# all of the supplied options
	#
	def import_options(options)
		options.each_option { |name, opt|
			if (opt.default)
				self.store(name, opt.default)
			end
		}
	end

	#
	# Imports option values from a whitespace separated string in
	# VAR=VAL format.
	#
	def import_options_from_s(option_str)
		hash = {}
	
		# Figure out the deliminter, default to space.
		delim = /\s/

		if (option_str.index(','))
			delim = ','
		end
		
		# Split on the deliminter
		option_str.split(delim).each { |opt|
			var, val = opt.split('=')

			# Invalid parse?  Raise an exception and let those bastards know.
			if (var == nil or val == nil)
				var = "unknown" if (!var)

				raise ArgumentParseError, "Invalid option specified: #{var}", caller
			end

			# Store the value
			hash[var] = val
		}

		import_options_from_hash(hash)
	end

	#
	# Imports options from a hash
	#
	def import_options_from_hash(option_hash)
		option_hash.each_pair { |key, val|
			self.store(key, val)
		}
	end

	#
	# Serializes the options in the datastore to a string
	#
	def to_s(delim = ' ')
		str = ''

		keys.sort.each { |key|
			str += "#{key}=#{self[key]}" + ((str.length) ? delim : '')
		}

		return str
	end
end

end
