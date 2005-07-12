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

	###
	#
	# Bruteforce
	# ----------
	#
	# Target-specific brute force information, such as the addresses
	# to step, the step size (if the framework default is bad), and
	# other stuff.
	#
	###
	class Bruteforce < Hash
		def initialize(hash)
			update(hash)
		end

		#
		# Returns a hash of addresses that should be stepped during
		# exploitation and passed in to the bruteforce exploit
		# routine.
		#
		def start_addresses
			if (self['Start'] and self['Start'].kind_of?(Hash) == false)
				return {'Address' => self['Start'] } 
			else
				return self['Start']
			end
		end

		#
		# Returns a hash of addresses that should be stopped at once
		# they are reached.
		#
		def stop_addresses
			if (self['Stop'] and self['Stop'].kind_of?(Hash) == false)
				return {'Address' => self['Stop'] } 
			else
				return self['Stop']
			end
		end

		#
		# The step size to use, or zero if the framework should figure
		# it out.
		#
		def step_size
			self['Step'] || 0
		end

		#
		# Returns the default step direction
		#
		def default_direction
			dd = self['DefaultDirection']

			if (dd and dd.to_s.match(/(-1|backward)/i))
				return -1
			end

			return 1
		end

		#
		# The delay to add between attempts
		#
		def delay
			self['Delay'].to_i || 0
		end
	end

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
		self.opts           = opts

		# Does this target have brute force information?
		if (opts['Bruteforce'])
			self.bruteforce = Bruteforce.new(opts['Bruteforce'])
		end
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

