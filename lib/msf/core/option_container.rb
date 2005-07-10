require 'resolv'
require 'msf/core'

module Msf

###
#
# OptBase
# -------
#
# The base class for all options.
#
###
class OptBase

	def initialize(in_name, attrs = [])
		self.name     = in_name
		self.advanced = false
		self.required = attrs[0] || false
		self.desc     = attrs[1]
		self.default  = attrs[2]
	end

	def required?
		return required
	end

	def advanced?
		return advanced
	end

	def type?(in_type)
		return (type == in_type)
	end

	# If it's required and the value is nil or empty, then it's not valid.
	def valid?(value)
		return (required? and (value == nil or value.to_s.empty?)) ? false : true
	end

	attr_reader   :name, :required, :desc, :default
	attr_writer   :name
	attr_accessor :advanced
	attr_accessor :owner

protected

	attr_writer   :required, :desc, :default
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
#
###

class OptString < OptBase
	def type 
		return 'string' 
	end
end

class OptRaw < OptBase
	def type
		return 'raw'
	end
end

class OptBool < OptBase
	def type
		return 'bool'
	end

	def valid?(value)
		if ((value != nil and value.empty? == false) and
		    (value.match(/^(y|n|t|f|0|1|true|false)$/i) == nil))
			return false
		end
	end

	def is_true?
		return (value.match(/^(y|t|1|true)$/i) != nil) ? true : false
	end

	def is_false?
		return !is_true?
	end
end

class OptPort < OptBase
	def type 
		return 'port' 
	end

	def valid?(value)
		if ((value != nil and value.to_s.empty? == false) and
		    ((value.to_i < 0 or value.to_i > 65535)))
			return false
		end

		return super
	end
end

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
# OptionContainer
# ---------------
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
		add_options(opts)
	end

	#
	# Return the value associated with the supplied name
	#
	def [](name)
		return get(name)
	end

	#
	# Return the option associated with the supplied name
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

	# Adds one or more options
	def add_options(opts, owner = nil, advanced = false)
		return false if (opts == nil)

		if (opts.kind_of?(Array))
			add_options_array(opts, owner, advanced)
		else
			add_options_hash(opts, owner, advanced)
		end

	end

	#
	# Add options from a hash of names
	#
	def add_options_hash(opts, owner = nil, advanced = false)
		opts.each_pair { |name, opt|
			add_option(opt, name, owner, advanced)
		}
	end

	#
	# Add options from an array of option instances or arrays
	#
	def add_options_array(opts, owner = nil, advanced = false)
		opts.each { |opt|
			add_option(opt, nil, owner, advanced)
		}
	end

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
	end

	# Alias to add advanced options that sets the proper state flag
	def add_advanced_options(opts, owner = nil)
		return false if (opts == nil)

		add_options(opts, owner, true)
	end

	# Make sures that each of the options has a value of a compatible 
	# format and that all the required options are set
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

	# Enumerates each option name
	def each_option(&block)
		each_pair(&block)
	end

end

#
# Builtin framework options with shortcut methods
#
module Opt

@@builtin_opts = 
	{
		'RHOST' => [ OptAddress, 'nil',   true,  '"The target address."' ],
		'RPORT' => [ OptPort,    'nil',   true,  '"The target port."' ],
		'LHOST' => [ OptAddress, 'nil',   true,  '"The local address."' ],
		'LPORT' => [ OptPort,    'nil',   true,  '"The local port."' ],
		'CPORT' => [ OptPort,    'nil',   false, '"The local client port."' ],
		'SSL'   => [ OptBool,    'false', false, '"Use SSL."' ],
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
