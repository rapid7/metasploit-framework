require 'resolv'
require 'Core'

module Msf

###
#
# DataStoreOption
# ---------------
#
# A data store option is an option that is stored in a data store! It contains
# meta information about the type of option being stored, such as type, as 
# well as the option's actual value
#
###
class DataStoreOption

	def initialize(in_name, attrs = [])
		self.name          = in_name
		self.advanced      = false
		self.required      = attrs[0] || false
		self.desc          = attrs[1] || nil
		self.default_value = attrs[2] || nil
		self.value         = self.default_value
	end

	def empty?
		return (value == nil)
	end

	def required?
		return required
	end

	def advanced?
		return advanced
	end

	def valid?
		return (empty? and required?) ? false : true
	end

	def type?(in_type)
		return (type == in_type)
	end

	def reset
		value = default_value
	end

	attr_reader   :name, :required, :desc, :default_value, :value
	attr_writer   :name, :value
	attr_accessor :advanced

protected

	attr_writer   :required, :desc, :default_value
end

###
#
# Core data store option types.  The core supported option types are:
#
# OptString  - Multi-byte character string
# OptRaw     - Multi-byte raw string
# OptBool    - Boolean true or false indication
# OptPort    - TCP/UDP service port
# OptAddress - IP address or hostname
# OptPath    - Path name on disk
#
###

class OptString < DataStoreOption
	def type 
		return 'string' 
	end
end

class OptRaw < DataStoreOption
	def type
		return 'raw'
	end
end

class OptBool < DataStoreOption
	def type
		return 'bool'
	end

	def valid?
		if ((empty? == false) and
		    (value.match(/^(y|n|t|f|0|1)$/i) == nil))
			return false
		end
	end

	def is_true?
		return (value.match(/^(y|t|1)$/i) != nil) ? true : false
	end

	def is_false?
		return !is_true?
	end
end

class OptPort < DataStoreOption
	def type 
		return 'port' 
	end

	def valid?
		if ((empty? == false) and
		    ((value.to_i < 0 or value.to_i > 65535)))
			return false
		end

		return super
	end
end

class OptAddress < DataStoreOption
	def type 
		return 'address' 
	end

	def valid?
		if (empty? == false)
			begin
				Resolv.getaddress(value)
			rescue
				return false
			end
		end

		return super
	end
end

class OptPath < DataStoreOption
	def type 
		return 'path' 
	end

	def valid?
		if ((empty? == false) and
		    (File.exists?(value) == false))
			return false
		end

		return super
	end
end

###
#
# DataStore
# ---------
#
# The data store's purpose in life is to associate named options
# with arbitrary values at the most simplistic level.  Each
# module contains a DataStore that is used to hold the 
# various options that the module depends on.  Example of options
# that are stored in the DataStore are RHOST and RPORT for
# payloads or exploits that need to connect to a host and
# port, for instance.
#
###
class DataStore < Hash

	# Merges in the supplied options and converts them to a DataStoreOption
	# as necessary.
	def initialize(opts = {})
		add_options(opts)
	end

	# Return the value associated with the supplied name
	def [](name)
		return get(name)
	end

	# Set the value associated with the supplied name
	def set(name, value)
		option = fetch(name)

		if (option == nil)
			return false
		end

		option.value = value

		return true
	end

	# Return the option associated with the supplied name
	def get(name)
		return fetch(name)
	end

	# Return the value associated with the supplied name
	def get_value(name)
		return fetch(name).value
	end

	# Adds one or more options
	def add_options(opts)
		return false if (opts == nil)

		opts.each_key { |name|
			option = opts[name]

			# Skip flags
			next if (name.match(/^_Flag/))

			if (option.kind_of?(Array))
				option = option.shift.new(name, option)
			elsif (!option.kind_of?(DataStoreOption))
				raise ArgumentError, 
					"The option named #{name} did not come in a compatible format.", 
					caller
			end

			option.name = name

			# If the advanced flag was supplied, flag the new option as being
			# an advanced option
			if (opts['_FlagAdvanced'] == true)
				option.advanced = true
			end

			self.store(name, option)
		}
	end

	# Alias to add advanced options that sets the proper state flag
	def add_advanced_options(opts = {})
		opts['_FlagAdvanced'] = true if (opts)

		add_options(opts)
	end

	# Make sures that each of the options has a value of a compatible 
	# format and that all the required options are set
	def validate
		errors = []

		each_pair { |name, option| 
			if (!option.valid?)
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

module Test

###
#
# DataStoreTestCase
# -----------------
#
# This class implements some testing routines for ensuring that the data
# store is operating correctly.
#
###
class DataStoreTestCase < ::Test::Unit::TestCase
	# Tests the initialization of the DataStore object
	def test_initialize
		# Make sure initialization works
		ds = nil

		assert_block("initialize failed") {
			ds = DataStore.new(
				'RHOST' => [ OptAddress, true, 'host.com' ],
				'RPORT' => [ OptPort,    true, 1234       ])

			if (ds == nil)
				false
			end

			true
		}

		# Make sure there are 2 options
		assert_equal(2, ds.length, "invalid number of options #{ds.length}")

		# Make sure that the constructor raises an argument error when
		# an invalid option is supplied
		assert_raise(ArgumentError, "initialize invalid failed") {
			DataStore.new(
				'RHOST' => 'invalid');
		}
	end

	# Tests getting the value of an option
	def test_get
		ds = DataStore.new(
			'RPORT' => [ OptPort, true, nil, 1234 ])

		assert_equal(1234, ds.get_value('RPORT'), 
				"RPORT does not match")
		
		ds.set('RPORT', 1235)
		
		assert_equal(1235, ds.get_value('RPORT'), 
				"RPORT does not match (2)")

		assert_equal('RPORT', ds['RPORT'].name, 
				"option name does not match")
	end

	# Tests setting the value of an option
	def test_set
		assert_block("set failed") {
			ds = DataStore.new(
				'RHOST' => [ OptAddress ])

			ds.set('RHOST', 'host.com')

			if (ds.get_value('RHOST') != 'host.com')
				false
			else
				true
			end
		}
	end

	# Tests validation
	def test_validate
		# Test validating required options
		ds = DataStore.new(
			'RHOST' => [ OptAddress, true ],
			'RPORT' => [ OptPort,    true ],
			'LIB'   => [ OptString        ])

		assert_raise(OptionValidateError, "required validation failed") {
			ds.validate
		}

		# Test validating the form of individual options
		ds.set('RHOST', 'www.invalid.host.tldinvalid')
		ds.set('RPORT', 1234)

		assert_raise(OptionValidateError, "host validation failed") {
			ds.validate
		}

		# Make sure address validation does work
		ds.set('RHOST', 'www.google.com')

		assert_equal(true, ds.validate, "overall validation failed")

		# Make sure port validation does work
		ds.set('RPORT', 123452)

		assert_raise(OptionValidateError, "port validation failed") {
			ds.validate
		}
	end

	# Make sure advanced additions work
	def test_advanced
		ds = DataStore.new

		ds.add_advanced_options(
			'DONKEY' => [ OptString, false ])
			
		assert_equal(true, ds.get('DONKEY').advanced?, 
				"advanced option failed")
	end
end

end

end
