require 'msf/core'

module Msf

###
#
# EncodedPayload
# --------------
#
# This class wrappers an encoded payload buffer and the means used to create
# one.
#
###
class EncodedPayload

	include Framework::Offspring

	#
	# Creates an encoded payload instance
	#
	def self.create(framework, pinst, reqs)
		# Create the encoded payload instance
		p = EncodedPayload.new(framework, pinst, reqs)

		p.generate

		return p
	end

	def initialize(framework, pinst, reqs)
		self.framework = framework
		self.pinst     = pinst
		self.reqs      = reqs
	end

	#
	# Generate the full encoded payload
	#
	def generate
		raw           = nil
		encoded       = nil
		nop_sled_size = 0
		nop_sled      = nil

		# Generate the raw version of the payload first
		generate_raw()

		# Encode the payload
		encode()

		# Build the NOP sled
		generate_sled()

		# Finally, set the complete payload definition
		encoded = (nop_sled || '') + encoded

		# Return the complete payload
		return encoded
	end

	#
	# Generates the raw payload from the payload instance.  This populates the
	# raw attribute.
	#
	def generate_raw
		raw = (reqs['Prepend'] || '') + pisnt.generate + (reqs['Append'] || '')
	end

	#
	# Scans for a compatible encoder using ranked precedence and populates the
	# encoded attribute.
	#
	def encode
		# If the exploit has bad characters, we need to run the list of encoders
		# in ranked precedence and try to encode without them.
		if (reqs['BadChars'])
			pinst.compatible_encoders.each { |enc|
				encoder = enc.new
			
				# Try encoding with the current encoder
				begin
					p.encoded = encoder.encode(raw, reqs['BadChars'])
				rescue
					wlog("#{pinst.refname}: Failed to encode payload with encoder #{encoder.refname}: #{$!}",
						'core', LEV_1)
				end

				# Minimum number of NOPs to use
				min = reqs['MinNops'] || 0

				# Check to see if we have enough room for the minimum requirements
				if ((reqs['Space']) and
				    (reqs['Space'] < encoded.length + min))
					wlog("#{pinst.refname}: Encoded payload version is too large with encoder #{encoder.refname}",
						'core', LEV_1)
					next
				end
			}
			
			# If the encoded payload is nil, raise an exception saying that we
			# suck at life.
			if (encoded == nil)
				raise NoEncodersSucceededError, 
					"#{pinst.refname}: All encoders failed to encode.",
					caller
			end
		# If there are no bad characters, then the raw is the same as the
		# encoded
		else
			encoded = raw
		end

		# Prefix the prepend encoder value
		encoded = (reqs['PrependEncoder'] || '') + encoded
	end

	#
	# Construct a NOP sled if necessary
	#
	def generate_sled
		min   = reqs['MinNops'] || 0
		space = reqs['Space']

		nop_sled_size = 0

		# Calculate the number of NOPs to pad out the buffer with based on the
		# requirements.  If there was a space requirement, check to see if
		# there's any room at all left for a sled.
		if ((space) and 
			 (space > encoded.length))
			nop_sled_size = reqs['Space'] - encoded.length
		end

		# If the maximum number of NOPs has been exceeded, wrap it back down.
		if ((reqs['MaxNops']) and
			 (reqs['MaxNops'] > sled_size))
			nop_sled_size = reqs['MaxNops']
		end

		# Now construct the actual sled
		if (nop_sled_size > 0)
			pinst.compatible_nops.each { |nopmod|
				# Create an instance of the nop module
				nop = nopmod.new
	
				begin
					nop_sled = nop.generate_sled(nop_sled_size,
						'BadChars'      => reqs['BadChars'],
						'SaveRegisters' => reqs['SaveRegisters'])	
				rescue
					dlog("#{pinst.refname}: Nop generator #{nop.refname} failed to generate sled for payload: #{$!}",
						'core', LEV_1)
				end
			}

			if (nop_sled == nil)
				raise NoNopsSucceededError, 
					"#{pinst.refname}: All NOP generators failed to construct sled for.",
					caller
			end
		else
			nop_sled = ''
		end

		return nop_sled
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

protected

	attr_writer :raw
	attr_writer :encoded
	attr_writer :nop_sled_size
	attr_writer :nop_sled
	attr_writer :payload

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
