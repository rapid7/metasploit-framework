require 'msf/core'

###
#
# Base mixin interface for use by stagers.
#
###
module Msf::Payload::Stager

	#
	# Sets the payload type to a stager.
	#
	def payload_type
		return Msf::Payload::Type::Stager
	end

	#
	# Return the stager payload's raw payload.
	#
	def payload
		return module_info['Stager']['Payload']	
	end

	#
	# Return the stager payload's assembly text, if any.
	#
	def assembly
		return module_info['Stager']['Assembly']
	end

	#
	# Return the stager payload's offsets.
	#
	def offsets
		return module_info['Stager']['Offsets']
	end

	#
	# Returns the raw stage payload.
	#
	def stage_payload
		return module_info['Stage']['Payload']
	end

	#
	# Returns the assembly text of the stage payload.
	#
	def stage_assembly
		return module_info['Stage']['Assembly']
	end

	#
	# Returns variable offsets within the stage payload.
	#
	def stage_offsets
		return module_info['Stage']['Offsets']
	end

	#
	# Whether or not any stages associated with this stager should be sent over
	# the connection that is established.
	#
	def stage_over_connection?
		true
	end

	#
	# Generates the stage payload and substitutes all offsets.
	#
	def generate_stage
		# Compile the stage as necessary
		p = build(stage_payload, stage_assembly, stage_offsets, '-stg1')

		# Substitute variables in the stage
		substitute_vars(p, stage_offsets) if (stage_offsets)

		# Encode the stage of stage encoding is enabled
		#p = encode_stage(p)

		return p
	end

	#
	# Transmit the associated stage.
	#
	def handle_connection(conn)
		# If the stage should be sent over the client connection that is
		# established (which is the default), then go ahead and transmit it.
		if (stage_over_connection?)
			p = generate_stage

			# Give derived classes an opportunity to an intermediate state before
			# the stage is sent.  This gives derived classes an opportunity to
			# augment the stage and the process through which it is read on the
			# remote machine.
			#
			# If we don't use an intermediate stage, then we need to prepend the
			# stage prefix, such as a tag
			if handle_intermediate_stage(conn, p) == false
				p = (self.stage_prefix || '') + p
			end

			print_status("Sending stage (#{p.length} bytes)")

			# Send the stage
			conn.put(p)
		end

		# If the stage implements the handle connection method, sleep before
		# handling it.
		if (derived_implementor?(Msf::Payload::Stager, 'handle_connection_stage'))
			print_status("Sleeping before handling stage...")

			# Sleep before processing the stage
			Rex::ThreadSafe.sleep(1.5)
		end

		# Give the stages a chance to handle the connection
		handle_connection_stage(conn)
	end

	#
	# Called by handle_connection to allow the stage to process
	# whatever it is it needs to process.  The default is to simply attempt to
	# create a session.
	#
	def handle_connection_stage(conn)
		create_session(conn)	
	end

	#
	# Gives derived classes an opportunity to alter the stage and/or
	# encapsulate its transmission.
	#
	def handle_intermediate_stage(conn, payload)
		false
	end

	# Encodes the stage prior to transmission
	def encode_stage(stg)

		# If DisableStageEncoding is set, we do not encode the stage
		return stg if datastore['DisableStageEncoding'] =~ /^(y|1|t)/i

		# Generate an encoded version of the stage.  We tell the encoding system
		# to save edi to ensure that it does not get clobbered.
		encp = Msf::EncodedPayload.create(
			self, 
			'Raw'           => stg,
			'SaveRegisters' => ['edi'],
			'ForceEncode'   => true)

		# If the encoding succeeded, use the encoded buffer.  Otherwise, fall
		# back to using the non-encoded stage
		encp.encoded || stg
	end

	# Aliases
	alias stager_payload payload
	alias stager_offsets offsets

	#
	# A value that should be prefixed to a stage, such as a tag.
	#
	attr_accessor :stage_prefix

end