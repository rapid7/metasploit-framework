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
	def self.create(pinst, reqs = {})
		# Create the encoded payload instance
		p = EncodedPayload.new(pinst.framework, pinst, reqs)

		p.generate(reqs['Raw'])

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
	def generate(raw = nil)
		self.raw           = raw
		self.encoded       = nil
		self.nop_sled_size = 0
		self.nop_sled      = nil
		self.encoder       = nil
		self.nop           = nil

		# Increase thread priority as necessary.  This is done
		# to ensure that the encoding and sled generation get
		# enough time slices from the ruby thread scheduler.
		priority = Thread.current.priority

		if (priority == 0)
			Thread.current.priority = 1
		end

		begin
			# First, validate
			pinst.validate()

			# Generate the raw version of the payload first
			generate_raw() if self.raw.nil?

			# Encode the payload
			encode()

			# Build the NOP sled
			generate_sled()

			# Finally, set the complete payload definition
			self.encoded = (self.nop_sled || '') + self.encoded
		ensure	
			# Restore the thread priority
			Thread.current.priority = priority
		end

		# Return the complete payload
		return encoded
	end

	#
	# Generates the raw payload from the payload instance.  This populates the
	# raw attribute.
	#
	def generate_raw
		self.raw = (reqs['Prepend'] || '') + pinst.generate + (reqs['Append'] || '')

		# If an encapsulation routine was supplied, then we should call it so
		# that we can get the real raw payload.
		if reqs['EncapsulationRoutine']
			self.raw = reqs['EncapsulationRoutine'].call(reqs, raw)
		end
	end

	#
	# Scans for a compatible encoder using ranked precedence and populates the
	# encoded attribute.
	#
	def encode
		# If the exploit has bad characters, we need to run the list of encoders
		# in ranked precedence and try to encode without them.
		if reqs['BadChars'] or reqs['Encoder'] or reqs['ForceEncode']
			encoders = pinst.compatible_encoders

			# If the caller had a preferred encoder, use this encoder only
			if ((reqs['Encoder']) and (preferred = framework.encoders[reqs['Encoder']]))
				encoders = [ [reqs['Encoder'], preferred] ]
			elsif (reqs['Encoder'])
				wlog("#{pinst.refname}: Failed to find preferred encoder #{reqs['Encoder']}")
				raise NoEncodersSucceededError, "Failed to find preferred encoder #{reqs['Encoder']}"
			end

			encoders.each { |encname, encmod|
				self.encoder = encmod.new
				self.encoded = nil

				# If there is an encoder type restriction, check to see if this
				# encoder matches with what we're searching for.
				if ((reqs['EncoderType']) and
				    (self.encoder.encoder_type.split(/\s+/).include?(reqs['EncoderType']) == false))
					wlog("#{pinst.refname}: Encoder #{encoder.refname} is not a compatible encoder type: #{reqs['EncoderType']} != #{self.encoder.encoder_type}",
						'core', LEV_1)
				
					next
				end

				# If the exploit did not explicitly request a kind of encoder and
				# the current encoder has a manual ranking, then it should not be
				# considered as a valid encoder.  A manual ranking tells the
				# framework that an encoder must be explicitly defined as the
				# encoder of choice for an exploit.
				if ((reqs['EncoderType'].nil?) and
				    (reqs['Encoder'].nil?) and
				    (self.encoder.rank == ManualRanking))
					wlog("#{pinst.refname}: Encoder #{encoder.refname} is manual ranked and was not defined as a preferred encoder.",
						'core', LEV_1)
					
					next
				end
	
				# If we have any encoder options, import them into the datastore
				# of the encoder.
				if (reqs['EncoderOptions'])
					self.encoder.datastore.import_options_from_hash(reqs['EncoderOptions'])
				end

				# Validate the encoder to make sure it's properly initialized.
				begin 
					self.encoder.validate
				rescue ::Exception
					wlog("#{pinst.refname}: Failed to validate encoder #{encoder.refname}: #{$!}",
						'core', LEV_1)
					
					next
				end
		
				# Try encoding with the current encoder
				begin
					self.encoded = self.encoder.encode(self.raw, reqs['BadChars'])
				rescue ::Exception
					wlog("#{pinst.refname}: Failed to encode payload with encoder #{encoder.refname}: #{$!}",
						'core', LEV_1)

					dlog("#{pinst.refname}: Call stack\n#{$@.join("\n")}", 'core', LEV_3)

					next
				end

				dlog("#{pinst.refname}: Successfully encoded with encoder #{encoder.refname} (size is #{self.encoded.length})", 
					'core', LEV_2)

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
			nops = pinst.compatible_nops

			# If the caller had a preferred nop, try to find it and prefix it
			if ((reqs['Nop']) and
			    (preferred = framework.nops[reqs['Nop']]))
				nops.unshift([reqs['Nop'], preferred ])
			elsif (reqs['Nop'])
				wlog("#{pinst.refname}: Failed to find preferred nop #{reqs['Nop']}")
			end

			nops.each { |nopname, nopmod|
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
