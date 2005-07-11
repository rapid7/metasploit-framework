require 'msf/core'
require 'msf/core/module_manager'

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

		# Initialize the hash entry for each type to an empty list
		[
			Payload::Type::Single,
			Payload::Type::Stager,
			Payload::Type::Stage
		].each { |type|
			self.payload_type_modules[type] = []
		}
	end

	# Build the actual hash of alias names based on all the permutations
	# of singles, stagers, and stages
	def recalculate
		# Reset the current hash associations
		self.each_key { |key|
			manager.delete(key)
		}
		self.clear

		# Recalculate single payloads
		singles.each { |p|
			mod, name, handler = p

			# Build the payload dupe using the determined handler
			# and module
			p = build_payload(handler, mod)

			# Sets the modules derived name
			p.refname = name

			# Associate this class with the single payload's name
			self[name] = p

			manager.add_module(p, name)

			dlog("Built single payload #{name}.", 'core', LEV_1)
		}

		# Recalculate stagers and stages
		stagers.each { |p|
			stager_mod, stager_name, handler, stager_platform, stager_arch = p

			# Walk the array of stages
			stages.each { |p|
				stage_mod, stage_name, junk, stage_platform, stage_arch = p

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
					dlog("  Stager: #{stager_platform.names}.", 'core', LEV_3)
					dlog("  Stage: #{stage_platform.names}.", 'core', LEV_3)
				end

				# Build the payload dupe using the handler, stager,
				# and stage
				p = build_payload(handler, stager_mod, stage_mod)

				# Associate the name as a combination of the stager and stage
				combined  = stage_name

				# If a valid handler exists for this stager, then combine it
				combined += '/stg/' + handler.handler_type if (handler)

				# Sets the modules derived name
				p.refname = combined

				self[combined] = p

				manager.add_module(p, combined)
			
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
	def add_module(pmodule, name)
		if (md = name.match(/^(singles|stagers|stages)#{File::SEPARATOR}(.*)$/))
			name = md[2]
		end

		# Duplicate the Payload base class and extend it with the module
		# class that is passed in.  This allows us to inspect the actual
		# module to see what type it is, and to grab other information for
		# our own evil purposes.
		instance = build_payload(pmodule).new

		# Create an array of information about this payload module
		pinfo = 
			[
				pmodule,
				instance.alias || name,
				instance.handler,
				instance.platform,
				instance.arch
			]

		# Store the module and alias name for this payload.  We
		# also convey other information about the module, such as
		# the platforms and architectures it supports
		payload_type_modules[instance.payload_type] << pinfo

		# If the payload happens to be a single, but has no defined
		# connection, then it can also be staged.  Insert it into
		# the staged list.
		if ((instance.payload_type == Payload::Type::Single) and
		    (instance.handler == nil))
			payload_type_modules[Payload::Type::Stage] << pinfo
		end
	end

protected

	# Builds a duplicate, extended version of the Payload base
	# class using the supplied modules.
	def build_payload(*modules)
		klass = Class.new(Payload)

		# Remove nil modules
		modules.delete_if { |x| x == nil }

		# Include the modules supplied to us with the mad skillz
		# spoonfu style
		klass.include(*modules)

		return klass
	end


	attr_accessor :manager, :payload_type_modules

end

end
