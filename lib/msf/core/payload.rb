require 'msf/core'

module Msf

###
#
# Payload
# -------
#
# This class represents the base class for a logical payload.  The framework
# automatically generates payload combinations at runtime which are all
# extended for this Payload as a base class.
#
###
class Payload < Msf::Module

	require 'msf/core/payload/single'
	require 'msf/core/payload/stager'

	# Platform specific includes
	require 'msf/core/payload/windows'

	#
	# Payload types
	#
	module Type
		Single = (1 << 0)
		Stager = (1 << 1)
		Stage  = (1 << 2)
	end

	def initialize(info = {})
		super
	end

	##
	#
	# Accessors
	#
	##

	#
	# This module is a payload.
	#
	def type
		return MODULE_PAYLOAD
	end

	#
	# Returns the string of bad characters for this payload, if any.
	#
	def badchars
		return self.module_info['BadChars']
	end

	#
	# Returns the type of payload, either single or staged.  Stage is
	# the default because singles and stagers are encouraged to include
	# the Single and Stager mixin which override the payload_type.
	#
	def payload_type
		return Type::Stage
	end

	#
	# Returns the payload's size.  If the payload is staged, the size of the
	# first stage is returned.
	#
	def size
		return (generate() || '').length
	end

	#
	# Returns the raw payload that has not had variable substitution occur.
	#
	def payload
		return module_info['Payload']['Payload']
	end

	#
	# Returns the offsets to variables that must be substitute, if any.
	#
	def offsets
		return module_info['Payload']['Offsets']
	end

	#
	# Return the connection associated with this payload, or none if there
	# isn't one.
	#
	def handler
		return module_info['Handler']
	end

	##
	#
	# Generation & variable substitution
	#
	##

	#
	# Generates the payload and return the raw buffer
	#
	def generate
		raw = payload

		# If the payload is generated and there are offsets to substitute,
		# do that now.
		if (raw and offsets)
			substitute_vars(raw, offsets)
		end

		return raw
	end

	#
	# Substitutes variables with values from the module's datastore in the
	# supplied raw buffer for a given set of named offsets.  For instance,
	# RHOST is substituted with the RHOST value from the datastore which will
	# have been populated by the framework.
	#
	def substitute_vars(raw, offsets)
		offsets.each_pair { |name, info|
			offset, pack = info

			# Give the derived class a chance to substitute this variable
			next if (replace_var(raw, name, offset, pack) == true)

			# Now it's our turn...
			if ((val = datastore[name]))
				if (pack == 'ADDR')
					val = Rex::Socket.resolv_nbo(val)
				elsif (pack == 'RAW')
					# Just use the raw value...
				else
					# NOTE:
					# Packing assumes integer format at this point, should fix...
					val = [ val.to_i ].pack(pack)	
				end

				# Substitute it
				raw[offset, val.length] = val
			else
				wlog("Missing value for payload offset #{name}, skipping.", 
					'core', LEV_1)
			end
		}
	end

	#
	# Replaces an individual variable in the supplied buffer at an offset
	# using the given pack type.  This is here to allow derived payloads
	# the opportunity to replace advanced variables.
	#
	def replace_var(raw, name, offset, pack)
		return false
	end

	##
	#
	# Shortcut methods for filtering compatible encoders
	# and NOP sleds
	#
	##

	#
	# Returns the array of compatible encoders for this payload instance.
	#
	def compatible_encoders
		encoders = []

		framework.encoders.each_module_ranked(
			'Arch' => self.arch) { |entry|
			encoders << entry[1]
		}

		return encoders
	end

	#
	# Returns the array of compatible nops for this payload instance.
	#
	def compatible_nops
		nops = []

		framework.nops.each_module_ranked(
			'Arch' => self.arch) { |entry|
			nops << entry[1]
		}

		return nops
	end

	# Payload prepending and appending for various situations
	attr_accessor :prepend, :append, :prepend_encoder

protected

	##
	#
	# Custom merge operations for payloads
	#
	##

	#
	# Merge the name to prefix the existing one and separate them
	# with a comma
	#
	def merge_name(info, val)
		if (info['Name'])
			info['Name'] = val + ',' + info['Name']
		else
			info['Name'] = val
		end
	end

end

end
