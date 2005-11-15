require 'resolv'
require 'msf/core'

module Msf

###
#
# The base class for all options.
#
###
class OptBase

	#
	# Initializes a named option with the supplied attribute array.
	# The array is composed of three values.
	#
	# attrs[0] = required (boolean type)
	# attrs[1] = description (string)
	# attrs[2] = default value
	#
	def initialize(in_name, attrs = [])
		self.name     = in_name
		self.advanced = false
		self.required = attrs[0] || false
		self.desc     = attrs[1]
		self.default  = attrs[2]
	end

	#
	# Returns true if this is a required option.
	#
	def required?
		return required
	end

	#
	# Returns true if this is an advanced option.
	#
	def advanced?
		return advanced
	end

	#
	# Returns true if the supplied type is equivalent to this option's type.
	#
	def type?(in_type)
		return (type == in_type)
	end

	#
	# If it's required and the value is nil or empty, then it's not valid.
	#
	def valid?(value)
		return (required? and (value == nil or value.to_s.empty?)) ? false : true
	end

	#
	# Returns the value of the option as a string.
	#
	def to_s
		return value.to_s
	end

	#
	# The name of the option.
	#
	attr_reader   :name
	#
	# Whether or not the option is required.
	#
	attr_reader   :required
	#
	# The description of the option.
	#
	attr_reader   :desc
	#
	# The default value of the option.
	#
	attr_reader   :default
	#
	# Storing the name of the option.
	#
	attr_writer   :name
	#
	# Whether or not this is an advanced option.
	#
	attr_accessor :advanced
	#
	# The module or entity that owns this option.
	#
	attr_accessor :owner

protected

	attr_writer   :required, :desc, :default # :nodoc:
end

###
#
# Core option types.  The core supported option types are:
#
# OptString  - Multi-byte character string
# OptRaw     - Multi-byte raw string
# OptBool    - Boolean true or false indication
# OptPort    - TCP/UDP service port
# OptAddress - IP address or hostname
# OptPath    - Path name on disk
# OptInt     - An integer value
#
###

###
#
# Mult-byte character string option.
#
###
class OptString < OptBase
	def type 
		return 'string' 
	end
end

###
#
# Raw, arbitrary data option.
#
###
class OptRaw < OptBase
	def type
		return 'raw'
	end
end

###
#
# Boolean option.
#
###
class OptBool < OptBase
	def type
		return 'bool'
	end

	def valid?(value)
		if ((value != nil and value.empty? == false) and
		    (value.match(/^(y|yes|n|no|t|f|0|1|true|false)$/i) == nil))
			return false
		end

		true
	end

	def is_true?
		return (value.match(/^(y|yes|t|1|true)$/i) != nil) ? true : false
	end

	def is_false?
		return !is_true?
	end

	def to_s
		return is_true?.to_s
	end
end

###
#
# Network port option.
#
###
class OptPort < OptBase
	def type 
		return 'port' 
	end

	def valid?(value)
		if ((value != nil and value.to_s.empty? == false) and
		    ((value.to_s.match(/^\d+$/) == nil or value.to_i < 0 or value.to_i > 65535)))
			return false
		end

		return super
	end
end

###
#
# Network address option.
#
###
class OptAddress < OptBase
	def type 
		return 'address' 
	end

	def valid?(value)
		if (value != nil and value.empty? == false)
			begin
				Resolv.getaddress(value)
			rescue
				return false
			end
		end

		return super
	end
end

###
#
# File system path option.
#
###
class OptPath < OptBase
	def type 
		return 'path' 
	end

	def valid?(value)
		if ((value != nil and value.empty? == false) and
		    (File.exists?(value) == false))
			return false
		end

		return super
	end
end

###
#
# Integer option.
#
###
class OptInt < OptBase
	def type 
		return 'integer' 
	end

	def valid?(value)
		if (value.to_s.match(/^\d+$/) == nil)
			return false
		end

		return super
	end
end


###
#
# The options purpose in life is to associate named options
# with arbitrary values at the most simplistic level.  Each
# module contains a OptionContainer that is used to hold the 
# various options that the module depends on.  Example of options
# that are stored in the OptionContainer are rhost and rport for
# payloads or exploits that need to connect to a host and
# port, for instance.
#
###
class OptionContainer < Hash

	#
	# Merges in the supplied options and converts them to a OptBase
	# as necessary.
	#
	def initialize(opts = {})
		self.sorted = []

		add_options(opts)
	end

	#
	# Return the value associated with the supplied name.
	#
	def [](name)
		return get(name)
	end

	#
	# Return the option associated with the supplied name.
	#
	def get(name)
		begin
			return fetch(name)
		rescue
		end
	end

	#
	# Returns whether or not the container has any options,
	# excluding advanced.
	#
	def has_options?
		each_option { |name, opt|
			return true if (opt.advanced? == false)
		}
		
		return false
	end

	#
	# Returns whether or not the container has any advanced
	# options.
	#
	def has_advanced_options?
		each_option { |name, opt|
			return true if (opt.advanced? == true)
		}

		return false
	end

	#
	# Removes an option.
	#
	def remove_option(name)
		delete(name)
		sorted.each_with_index { |e, idx|
			sorted.delete_at(idx) if (e[0] == name)
		}
	end

	#
	# Adds one or more options.
	#
	def add_options(opts, owner = nil, advanced = false)
		return false if (opts == nil)

		if (opts.kind_of?(Array))
			add_options_array(opts, owner, advanced)
		else
			add_options_hash(opts, owner, advanced)
		end
	end

	#
	# Add options from a hash of names.
	#
	def add_options_hash(opts, owner = nil, advanced = false)
		opts.each_pair { |name, opt|
			add_option(opt, name, owner, advanced)
		}
	end

	#
	# Add options from an array of option instances or arrays.
	#
	def add_options_array(opts, owner = nil, advanced = false)
		opts.each { |opt|
			add_option(opt, nil, owner, advanced)
		}
	end

	#
	# Adds an option.
	#
	def add_option(option, name = nil, owner = nil, advanced = false)
		if (option.kind_of?(Array))
			option = option.shift.new(name, option)
		elsif (!option.kind_of?(OptBase))
			raise ArgumentError, 
				"The option named #{name} did not come in a compatible format.", 
				caller
		end

		option.advanced = advanced
		option.owner    = owner

		self.store(option.name, option)

		# Re-calculate the sorted list
		self.sorted = self.sort
	end

	#
	# Alias to add advanced options that sets the proper state flag.
	#
	def add_advanced_options(opts, owner = nil)
		return false if (opts == nil)

		add_options(opts, owner, true)
	end

	#
	# Make sures that each of the options has a value of a compatible 
	# format and that all the required options are set.
	#
	def validate(datastore)
		errors = []

		each_pair { |name, option| 
			if (!option.valid?(datastore[name]))
				errors << name
			end
		}
		
		if (errors.empty? == false)
			raise OptionValidateError.new(errors), 
				"One or more options failed to validate", caller
		end

		return true
	end

	#
	# Creates string of options that were used from the datastore in VAR=VAL
	# format separated by commas.
	#
	def options_used_to_s(datastore)
		used = ''

		each_pair { |name, option|
			next if (datastore[name] == nil)

			used += ", " if (used.length > 0)
			used += "#{name}=#{datastore[name]}"
		}

		return used
	end

	#
	# Enumerates each option name
	#
	def each_option(&block)
		each_pair(&block)
	end

	#
	# The sorted array of options.
	#
	attr_reader :sorted

protected

	attr_writer :sorted # :nodoc:

end

#
# Builtin framework options with shortcut methods
#
module Opt

@@builtin_opts = 
	{
		'RHOST' => [ OptAddress, 'nil',   true,  '"The target address"' ],
		'RPORT' => [ OptPort,    'nil',   true,  '"The target port"' ],
		'LHOST' => [ OptAddress, 'nil',   true,  '"The local address"' ],
		'LPORT' => [ OptPort,    'nil',   true,  '"The local port"' ],
		'CPORT' => [ OptPort,    'nil',   false, '"The local client port"' ],
		'SSL'   => [ OptBool,    'false', false, '"Use SSL"' ],
	}

#
# Build the builtin_xyz methods on the fly using the type information for each
# of the builtin framework options, such as RHOST.
#
class <<self
	@@builtin_opts.each_pair { |opt, info|
		eval(
			"
			def builtin_#{opt.downcase}(default = #{info[1]}, required = #{info[2]}, desc = #{info[3]})
				#{info[0]}.new('#{opt}', [ required, desc, default ])
			end

			alias #{opt} builtin_#{opt.downcase}
			")
	}
end

# 
# Define the constant versions of the options which are merely redirections to
# the class methods.
#
@@builtin_opts.each_pair { |opt, info|
	eval("#{opt} = Msf::Opt::builtin_#{opt.downcase}")
}

end

end
