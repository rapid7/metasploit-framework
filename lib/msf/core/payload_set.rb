require 'Msf/Core'
require 'Msf/Core/ModuleManager'

module Msf

###
#
# PayloadSet
# ----------
#
# This class is a special case of the generic module set class because
# payloads are generated in terms of combinations between various 
# components, such as a stager and a stage.  As such, the payload set
# needs to be built on the fly and cannot be simply matched one-to-one
# with a payload module.  Yeah, the term module is kind of overloaded
# here, but eat it!
#
###
class PayloadSet < ModuleSet

	def initialize(manager)
		super(MODULE_PAYLOAD)

		# A reference to the ModuleManager instance
		self.manager = manager

		# A hash of each of the payload types that holds an array
		# for all of the associated modules
		self.payload_type_modules = {}
	end

	# Build the actual hash of alias names based on all the permutations
	# of singles, stagers, and stages
	def recalculate
		# Reset the current hash associations
		full_names.clear
		alias_names.clear
		ambiguous_names.clear
		self.clear

		# Recalculate single payloads
		singles.each { |p|
			mod, name, connection = p

			# Get the payload's client-side handler
			handler = get_payload_handler(connection)

			# Build the payload dupe using the determined handler
			# and module
			p = build_payload(handler, mod)

			# Associate this class with the single payload's name
			self[name] = p

			dlog("Built single payload #{name}.", 'core', LEV_1)
		}

		# Recalculate stagers and stages
		stagers.each { |p|
			stager_mod, stager_name, stager_conn, stager_platform, stager_arch = p

			# Walk the array of stages
			stages.each { |p|
				stage_mod, stage_name, stage_conn, stage_platform, stage_arch = p
			
				# No intersection between architectures on the payloads?
				if ((stager_arch) and
				    (stage_arch) and
				    ((stager_arch & stage_arch).empty?))
					dlog("Stager #{stager_name} and stage #{stage_name} have incompatible architectures:",
						'core', LEV_3)
					dlog("  Stager: #{stager_arch.join}.", 'core', LEV_3)
					dlog("  Stage: #{stage_arch.join}.", 'core', LEV_3)
				end

				# No intersection between platforms on the payloads?
				if ((stager_platform) and
				    (stage_platform) and
				    (stager_platform & stage_platform).empty?)
					dlog("Stager #{stager_name} and stage #{stage_name} have incompatible platforms:",
						'core', LEV_3)
					dlog("  Stager: #{stager_platform.join}.", 'core', LEV_3)
					dlog("  Stage: #{stage_platform.join}.", 'core', LEV_3)
				end

				# Get the connection handler for the stager's connection
				handler = get_payload_handler(stager_conn)

				# Build the payload dupe using the handler, stager,
				# and stage
				p = build_payload(handler, stager_mod, stage_mod)

				# Associate the name as a combination of the stager and stage
				combined = stager_name + '_' + stage_name

				self[combined] = p
			
				dlog("Built staged payload #{combined}.", 'core', LEV_1)
			}
		}
	end

	# Return the array of single payloads
	def singles
		return payload_type_modules[Payload::Type::Single] || []
	end

	# Return the array of stager payloads
	def stagers
		return payload_type_modules[Payload::Type::Stager] || []
	end

	# Return the array of stage payloads
	def stages
		return payload_type_modules[Payload::Type::Stage] || []
	end

	# Called when a new payload module class is loaded up.  For the payload
	# set we simply create an instance of the class and do some magic to figure
	# out if it's a single, stager, or stage.  Depending on which it is, we 
	# add it to the appropriate list
	def add_module(short_name, full_name, pmodule)

		# Duplicate the Payload base class and extend it with the module
		# class that is passed in.  This allows us to inspect the actual
		# module to see what type it is, and to grab other information for
		# our own evil purposes.
		instance = build_payload(pmodule).new

		# Create and insert this module class into the array for 
		# its respective module type
		if (!payload_type_modules[instance.payload_type])
			payload_type_modules[instance.payload_type] = []	
		end

		# Store the module and alias name for this payload.  We
		# also convey other information about the module, such as
		# the platforms and architectures it supports
		payload_type_modules[instance.payload_type] <<
			[
				pmodule,
				instance.alias,
				instance.connection,
				instance.platform,
				instance.arch
			]
	end

protected

	# Returns the handler class responsible for the provided connection
	# type.
	def get_payload_handler(connection)
		return nil # TODO
	end

	# Builds a duplicate, extended version of the Payload base
	# class using the supplied modules.
	def build_payload(*modules)
		klass = Class.new(Payload)
		include_str = ''

		modules.each { |mod|
			# Skip nil modules
			next if (!mod)

			include_str += "include #{mod}\n"
		}

		# Evalulate the module includes and rock the house
		klass.class_eval(include_str)

		return klass
	end


	attr_accessor :manager, :payload_type_modules

end

end
