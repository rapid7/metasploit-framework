module Msf

###
#
# The data store is just a bitbucket that holds keyed values.  It is used
# by various classes to hold option values and other state information.
#
###
class DataStore < Hash

	#
	# Initializes the data store's internal state.
	#
	def initialize()
		@imported = Hash.new
	end

	#
	# Clears the imported flag for the supplied key since it's being set
	# directly.
	#
	def []=(k, v)
		@imported[k] = false

		super
	end

	#
	# Updates a value in the datastore with the specified name, k, to the
	# specified value, v.  This update does not alter the imported status of
	# the value.
	#
	def update_value(k, v)
		self.store(k, v)
	end

	#
	# This method is a helper method that imports the default value for
	# all of the supplied options
	#
	def import_options(options)
		options.each_option { |name, opt|
			# If the option has a default value, import it, but only if the
			# datastore doesn't already have a value set for it.
			if (opt.default and self[name] == nil)
				self.store(name, opt.default.to_s)

				@imported[name] = true
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

		if (option_str.split('=').length <= 2 or option_str.index(',') != nil)
			delim = ','
		end

		# Split on the deliminter
		option_str.split(delim).each { |opt|
			var, val = opt.split('=')

			next if (var =~ /^\s+$/)

			# Remove trailing whitespaces from the value
			val.gsub!(/\s+$/, '')

			# Invalid parse?  Raise an exception and let those bastards know.
			if (var == nil or val == nil)
				var = "unknown" if (!var)

				raise Rex::ArgumentParseError, "Invalid option specified: #{var}", 
					caller
			end

			# Store the value
			hash[var] = val
		}

		import_options_from_hash(hash)
	end

	#
	# Imports options from a hash and stores them in the datastore.
	#
	def import_options_from_hash(option_hash, imported = true)
		option_hash.each_pair { |key, val|
			self.store(key, val.to_s)

			@imported[key] = imported
		}
	end

	#
	# Serializes the options in the datastore to a string.
	#
	def to_s(delim = ' ')
		str = ''

		keys.sort.each { |key|
			str += "#{key}=#{self[key]}" + ((str.length) ? delim : '')
		}

		return str
	end

	#
	# Persists the contents of the data store to a file
	#
	def to_file(path, name = 'global')
		ini = Rex::Parser::Ini.new(path)

		ini.add_group(name)

		# Save all user-defined options to the file.
		user_defined.each_pair { |k, v|
			ini[name][k] = v
		}

		ini.to_file(path)
	end

	#
	# Imports datastore values from the specified file path using the supplied
	# name
	#
	def from_file(path, name = 'global')
		begin
			ini = Rex::Parser::Ini.from_file(path)
		rescue
			return
		end

		if (ini.group?(name))
			import_options_from_hash(ini[name], false)
		end
	end

	#
	# Returns a hash of user-defined datastore values.  The returned hash does
	# not include default option values.
	#
	def user_defined
		reject { |k, v|
			@imported[k] == true
		}
	end

	#
	# Remove all imported options from the data store.
	#
	def clear_non_user_defined
		@imported.delete_if { |k, v|
			self.delete(k) if (v)
			v
		}
	end

end

###
#
# DataStore wrapper for modules that will attempt to back values against the
# framework's datastore if they aren't found in the module's datastore.  This
# is done to simulate global data store values.
#
###
class ModuleDataStore < DataStore

	def initialize(m)
		super()

		@_module = m
	end

	#
	# Fetch the key from the local hash first, or from the framework datastore
	# if we can't directly find it
	#
	def fetch(key)
		val = super 

		if (val == nil and @_module and @_module.framework)
			val = @_module.framework.datastore[key]
		end

		return val
	end

	#
	# Same as fetch
	#
	def [](key)
		val = super
		
		if (val == nil and @_module and @_module.framework)
			val = @_module.framework.datastore[key]
		end

		return val
	end

end

end
