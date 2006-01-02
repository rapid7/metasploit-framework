require 'msf/core'

module Msf

###
#
# This class wrappers an encoded payload buffer and the means used to create
# one.
#
###
class EncodedPayload

	include Framework::Offspring

	#
	# This method creates an encoded payload instance and returns it to the
	# caller.
	#
	def self.create(pinst, reqs)
		# Create the encoded payload instance
		p = EncodedPayload.new(pinst.framework, pinst, reqs)

		p.generate

		return p
	end

	#
	# Creates an instance of an EncodedPayload.
	#
	def initialize(framework, pinst, reqs)
		self.framework = framework
		self.pinst     = pinst
		self.reqs      = reqs
	end

	#
	# This method enerates the full encoded payload and returns the encoded
	# payload buffer.
	#
	def generate
		self.raw           = nil
		self.encoded       = nil
		self.nop_sled_size = 0
		self.nop_sled      = nil
		self.encoder       = nil
		self.nop           = nil

		# First, validate
		pinst.validate()

		# Generate the raw version of the payload first
		generate_raw()

		# Encode the payload
		encode()

		# Build the NOP sled
		generate_sled()

		# Finally, set the complete payload definition
		self.encoded = (self.nop_sled || '') + self.encoded

		# Return the complete payload
		return encoded
	end

	#
	# Generates the raw payload from the payload instance.  This populates the
	# raw attribute.
	#
	def generate_raw
		self.raw = (reqs['Prepend'] || '') + pinst.generate + (reqs['Append'] || '')
	end

	#
	# Scans for a compatible encoder using ranked precedence and populates the
	# encoded attribute.
	#
	def encode
		# If the exploit has bad characters, we need to run the list of encoders
		# in ranked precedence and try to encode without them.
		if (reqs['BadChars'] or reqs['Encoder'])
			encoders = pinst.compatible_encoders

			# If the caller had a preferred encoder, try to find it and prefix it
			if ((reqs['Encoder']) and
			    (preferred = framework.encoders[reqs['Encoder']]))
				encoders.unshift([reqs['Encoder'], preferred ])
			elsif (reqs['Encoder'])
				wlog("#{pinst.refname}: Failed to find preferred encoder #{reqs['Encoder']}")
			end

			encoders.each { |encname, encmod|
				self.encoder = encmod.new
				self.encoded = nil
			
				# Try encoding with the current encoder
				begin
					self.encoded = self.encoder.encode(self.raw, reqs['BadChars'])
				rescue SyntaxError, ArgumentError
					wlog("#{pinst.refname}: Failed to encode payload with encoder #{encoder.refname}: #{$!}\n#{$@.join("\n")}",
						'core', LEV_1)
					next
				rescue
					wlog("#{pinst.refname}: Failed to encode payload with encoder #{encoder.refname}: #{$!}",
						'core', LEV_1)
					next
				end

				# Get the minimum number of nops to use
				min = (reqs['MinNops'] || 0).to_i
				min = 0 if reqs['DisableNops']
				

				# Check to see if we have enough room for the minimum requirements
				if ((reqs['Space']) and
				    (reqs['Space'] < self.encoded.length + min))
					wlog("#{pinst.refname}: Encoded payload version is too large with encoder #{encoder.refname}",
						'core', LEV_1)
					next
				end

				break
			}
			
			# If the encoded payload is nil, raise an exception saying that we
			# suck at life.
			if (self.encoded == nil)
				encoder = nil

				raise NoEncodersSucceededError, 
					"#{pinst.refname}: All encoders failed to encode.",
					caller
			end
		# If there are no bad characters, then the raw is the same as the
		# encoded
		else
			self.encoded = raw
		end

		# Prefix the prepend encoder value
		self.encoded = (reqs['PrependEncoder'] || '') + self.encoded
	end

	#
	# Construct a NOP sled if necessary
	#
	def generate_sled
		min   = reqs['MinNops'] || 0
		space = reqs['Space']

		self.nop_sled_size = min

		# Calculate the number of NOPs to pad out the buffer with based on the
		# requirements.  If there was a space requirement, check to see if
		# there's any room at all left for a sled.
		if ((space) and 
			 (space > encoded.length))
			self.nop_sled_size = reqs['Space'] - self.encoded.length
		end

		# If the maximum number of NOPs has been exceeded, wrap it back down.
		if ((reqs['MaxNops']) and
			 (reqs['MaxNops'] < self.nop_sled_size))
			self.nop_sled_size = reqs['MaxNops']
		end

		# Check for the DisableNops setting
		self.nop_sled_size = 0 if reqs['DisableNops']

		# Now construct the actual sled
		if (self.nop_sled_size > 0)
			pinst.compatible_nops.each { |nopname, nopmod|
				# Create an instance of the nop module
				self.nop = nopmod.new

				# The list of save registers
				save_regs = (reqs['SaveRegisters'] || []) + (pinst.save_registers || [])

				if (save_regs.empty? == true)
					save_regs = nil
				end

				begin
					nop.copy_ui(pinst)

					self.nop_sled = nop.generate_sled(self.nop_sled_size,
						'BadChars'      => reqs['BadChars'],
						'SaveRegisters' => save_regs)
				rescue
					dlog("#{pinst.refname}: Nop generator #{nop.refname} failed to generate sled for payload: #{$!}",
						'core', LEV_1)

					self.nop = nil
				end

				break
			}

			if (self.nop_sled == nil)
				raise NoNopsSucceededError, 
					"#{pinst.refname}: All NOP generators failed to construct sled for.",
					caller
			end
		else
			self.nop_sled = ''
		end

		return self.nop_sled
	end

	#
	# The raw version of the payload
	#
	attr_reader :raw
	#
	# The encoded version of the raw payload plus the NOP sled
	# if one was generated.
	#
	attr_reader :encoded
	#
	# The size of the NOP sled
	#
	attr_reader :nop_sled_size
	#
	# The NOP sled itself
	#
	attr_reader :nop_sled
	#
	# The encoder that was used
	#
	attr_reader :encoder
	#
	# The NOP generator that was used
	#
	attr_reader :nop

protected

	attr_writer :raw # :nodoc:
	attr_writer :encoded # :nodoc:
	attr_writer :nop_sled_size # :nodoc:
	attr_writer :nop_sled # :nodoc:
	attr_writer :payload # :nodoc:
	attr_writer :encoder # :nodoc:
	attr_writer :nop # :nodoc:

	#
	# The payload instance used to generate the payload
	#
	attr_accessor :pinst
	#
	# The requirements used for generation
	#
	attr_accessor :reqs

end

end
