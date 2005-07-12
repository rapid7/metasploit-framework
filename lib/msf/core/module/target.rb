require 'msf/core'

###
#
# Target
# ------
#
# A target for an exploit.
#
###
class Msf::Module::Target

	#
	# Serialize from an array to a Target instance
	#
	def self.from_a(ary)
		return nil if (ary.length < 2)

		self.new(ary.shift, ary.shift)
	end

	#
	# Transforms the supplied source into an array of Target's
	#
	def self.transform(src)
		Rex::Transformer.transform(src, Array, [ self, String ], 'Target')
	end

	#
	# Init it up!
	#
	def initialize(name, opts)
		opts = {} if (!opts)

		self.name           = name
		self.platforms      = Msf::Module::PlatformList.from_a(opts['Platform'])
		self.save_registers = opts['SaveRegisters']
		self.ret            = opts['Ret']
		self.bruteforce     = opts['Bruteforce']
		self.opts           = opts
	end

	#
	# Index the options directly
	#
	def [](key)
		opts[key]
	end

	#
	# Returns whether or not this is a bruteforce target, forces boolean
	# result.
	#
	def bruteforce?
		return (bruteforce != nil)
	end

	attr_reader :name, :platforms, :opts, :ret, :save_registers
	attr_reader :bruteforce

protected

	attr_writer :name, :platforms, :opts, :ret, :save_registers
	attr_writer :bruteforce

end

