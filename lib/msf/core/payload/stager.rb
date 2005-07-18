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

		substitute_vars(p, stage_offsets) if (stage_offsets)

		print_status("Sending stage (#{p.length} bytes)")

		conn.put(p)

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

end
