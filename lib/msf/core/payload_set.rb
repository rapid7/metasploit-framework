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
			self.payload_type_modules[type] = {}
		}

		# Initialize hashes for each of the stages and singles.  Stagers
		# never exist independent.  The stages hash will have entries that
		# point to another hash that point to the per-stager implementation
		# payload class.  For instance:
		#
		# ['windows/shell']['reverse_tcp']
		#
		# Singles will simply point to the single payload class.
		self.stages  = {}
		self.singles = {}

		# Hash that caches the sizes of payloads
		self.sizes   = {}
	end

	#
	# Performs custom filtering during each_module enumeration.  This allows us
	# to filter out certain stagers as necessary.
	#
	# TODO: stager-based customf iltering
	#
	def each_module_filter(opts, name, mod)
		return false
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
		_singles.each_pair { |name, p|
			mod, handler = p

			# Build the payload dupe using the determined handler
			# and module
			p = build_payload(handler, mod)

			# Sets the modules derived name
			p.refname = name

			# Add it to the set
			add_single(p, name)

			# Cache the payload's size
			sizes[name] = p.new.size
		}

		# Recalculate stagers and stages
		_stagers.each_pair { |stager_name, p|
			stager_mod, handler, stager_platform, stager_arch = p

			# Walk the array of stages
			_stages.each_pair { |stage_name, p|
				stage_mod, junk, stage_platform, stage_arch = p

				# No intersection between architectures on the payloads?
				if ((stager_arch) and
				    (stage_arch) and
				    ((stager_arch & stage_arch).empty?))
					dlog("Stager #{stager_name} and stage #{stage_name} have incompatible architectures:",
						'core', LEV_3)
					dlog("  Stager: #{stager_arch.join}.", 'core', LEV_3)
					dlog("  Stage: #{stage_arch.join}.", 'core', LEV_3)
					next
				end

				# No intersection between platforms on the payloads?
				if ((stager_platform) and
				    (stage_platform) and
				    (stager_platform & stage_platform).empty?)
					dlog("Stager #{stager_name} and stage #{stage_name} have incompatible platforms:",
						'core', LEV_3)
					dlog("  Stager: #{stager_platform.names}.", 'core', LEV_3)
					dlog("  Stage: #{stage_platform.names}.", 'core', LEV_3)
					next
				end

				# Build the payload dupe using the handler, stager,
				# and stage
				p = build_payload(handler, stager_mod, stage_mod)

				# Associate the name as a combination of the stager and stage
				combined  = stage_name

				# If a valid handler exists for this stager, then combine it
				combined += '/' + handler.handler_type

				# Sets the modules derived name
				p.refname = combined

				# Add the stage
				add_stage(p, combined, stage_name, handler.handler_type)
			
				# Cache the payload's size
				sizes[combined] = p.new.size
			}
		}
	end

	#
	# Called when a new payload module class is loaded up.  For the payload
	# set we simply create an instance of the class and do some magic to figure
	# out if it's a single, stager, or stage.  Depending on which it is, we 
	# add it to the appropriate list
	#
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
				instance.handler,
				instance.platform,
				instance.arch
			]

		# Use the module's preferred alias if it has one
		name = instance.alias if (instance.alias)

		# Store the module and alias name for this payload.  We
		# also convey other information about the module, such as
		# the platforms and architectures it supports
		payload_type_modules[instance.payload_type][name] = pinfo

		# If the payload happens to be a single, but has no defined
		# connection, then it can also be staged.  Insert it into
		# the staged list.
		if ((instance.payload_type == Payload::Type::Single) and
		    ((instance.handler == Msf::Handler::None) or
		     (instance.handler == nil)))
			payload_type_modules[Payload::Type::Stage][name] = pinfo
		end
	end

	#
	# Adds a single payload to the set and adds it to the singles hash
	#
	def add_single(p, name)
		p.framework = framework

		# Associate this class with the single payload's name
		self[name] = p

		# Add the singles hash
		singles[name] = p

		# Add it to the global module set
		manager.add_module(p, name)

		dlog("Built single payload #{name}.", 'core', LEV_1)
	end

	#
	# Adds a stage payload to the set and adds it to the stages hash
	# using the supplied handler type.
	#
	def add_stage(p, full_name, stage_name, handler_type)
		p.framework = framework

		# Associate this stage's full name with the payload class in the set
		self[full_name] = p

		# Add the full name association in the global module set
		manager.add_module(p, full_name)

		# Create the hash entry for this stage and then create
		# the associated entry for the handler type
		stages[stage_name] = {} if (!stages[stage_name])

		# Add it to this stage's stager hash
		stages[stage_name][handler_type] = p
			
		dlog("Built staged payload #{full_name}.", 'core', LEV_1)
	end

	attr_reader :stages, :singles, :sizes

protected

	#
	# Return the hash of single payloads
	#
	def _singles
		return payload_type_modules[Payload::Type::Single] || {}
	end

	#
	# Return the hash of stager payloads
	#
	def _stagers
		return payload_type_modules[Payload::Type::Stager] || {}
	end

	#
	# Return the hash of stage payloads
	#
	def _stages
		return payload_type_modules[Payload::Type::Stage] || {}
	end

	#
	# Builds a duplicate, extended version of the Payload base
	# class using the supplied modules.
	#
	def build_payload(*modules)
		klass = Class.new(Payload)

		# Remove nil modules
		modules.delete_if { |x| x == nil }

		# Include the modules supplied to us with the mad skillz
		# spoonfu style
		klass.include(*modules.reverse)

		return klass
	end

	attr_accessor :manager, :payload_type_modules
	attr_writer   :stages, :singles, :sizes

end

end
