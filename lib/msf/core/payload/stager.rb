require 'msf/core'

###
#
# Stager
# ------
#
# Base mixin interface for use by stagers.
#
###
module Msf::Payload::Stager

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
	# Returns variable offsets within the stage payload.
	#
	def stage_offsets
		return module_info['Stage']['Offsets']
	end

	#
	# Transmit the associated stage.
	#
	def handle_connection(conn)
		p = stage_payload.dup

		# Substitute variables in the stage
		substitute_vars(p, stage_offsets) if (stage_offsets)

		# Prefix to the stage with whatever may be required and then rock it.
		p = (stage_prefix || '') + p

		print_status("Sending stage (#{p.length} bytes)")

		# Send the stage
		conn.put(p)

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

	# Aliases
	alias stager_payload payload
	alias stager_offsets offsets

	#
	# A value that should be prefixed to a stage, such as a tag.
	#
	attr_accessor :stage_prefix

end
