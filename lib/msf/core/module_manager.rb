require 'find'
require 'msf/core'

module Msf

###
#
# ModuleSet
# ---------
#
# A module set contains zero or more named module classes of an arbitrary
# type.
#
###
class ModuleSet < Hash

	include Framework::Offspring

	def initialize(type = nil)
		self.module_type       = type

		# Hashes that convey the supported architectures and platforms for a
		# given module
		self.mod_arch_hash     = {}
		self.mod_platform_hash = {}
		self.mod_sorted        = nil
		self.mod_ranked        = nil
	end

	# Create an instance of the supplied module by its name
	def create(name)
		klass = self[name]
		
		return (klass) ? klass.new : nil
	end

	# Enumerates each module class in the set
	def each_module(opts = {}, &block)
		mod_sorted = self.sort if (mod_sorted == nil)
		
		each_module_list(mod_sorted, opts, &block)
	end

	def each_module_ranked(opts = {}, &block)
		mod_ranked = rank_modules if (mod_ranked == nil)

		each_module_list(mod_ranked, opts, &block)
	end

	#
	# Custom each_module filtering if an advanced set supports doing extended
	# filtering.  Returns true if the entry should be filtered.
	#
	def each_module_filter(opts, name, entry)
		return false
	end

	#
	# Dummy placeholder to relcalculate aliases and other fun things
	#
	def recalculate
	end

	attr_reader   :module_type

protected

	#
	# Enumerates the modules in the supplied array with possible limiting
	# factors.
	#
	def each_module_list(ary, opts, &block)
		ary.each { |entry|
			name, mod = entry

			# Filter out incompatible architectures
			if (opts['Arch'])
				if (!mod_arch_hash[mod])
					mod_arch_hash[mod] = mod.new.arch
				end

				next if ((mod_arch_hash[mod] & opts['Arch']).empty? == true)
			end		

			# Filter out incompatible platforms
			if (opts['Platform'])
				if (!mod_platform_hash[mod])
					mod_platform_hash[mod] = mod.new.platform
				end

				next if ((mod_platform_hash[mod] & opts['Platform']).empty? == true)
			end

			# Custom filtering
			next if (each_module_filter(opts, name, entry) == true)

			block.call(name, mod)
		}
	end

	#
	# Ranks modules based on their constant rank value, if they have one.
	#
	def rank_modules
		mod_ranked = self.sort { |a, b|
			a_name, a_mod = a
			b_name, b_mod = b

			# Extract the ranking between the two modules
			a_rank = a.const_defined?('Rank') ? a.const_get('Rank') : NormalRanking
			b_rank = b.const_defined?('Rank') ? b.const_get('Rank') : NormalRanking

			# Compare their relevant rankings.  Since we want highest to lowest,
			# we compare b_rank to a_rank in terms of higher/lower precedence
			b_rank <=> a_rank	
		}
	end

	#
	# Adds a module with a the supplied name
	#
	def add_module(module_class, name)
		# Duplicate the module class so that we can operate on a
		# framework-specific copy of it.
		dup = module_class.dup

		# Set the module's name so that it can be referenced when
		# instances are created.
		dup.framework = framework
		dup.refname   = name

		self[name] = dup
		
		# Invalidate the sorted array
		invalidate_cache
	end

	#
	# Invalidates the sorted and ranked module caches.
	#
	def invalidate_cache
		mod_sorted = nil
		mod_ranked = nil
	end

	attr_writer   :module_type
	attr_accessor :mod_arch_hash, :mod_platform_hash
	attr_accessor :mod_sorted, :mod_ranked

end

###
#
# ModuleManager
# -------------
#
# Upper management decided to throw in some middle management
# because the modules were getting out of hand.  This bad boy
# takes care of the work of managing the interaction with 
# modules in terms of loading and instantiation.
#
# TODO:
#
#   - add reload support
#   - add unload support
#
###
class ModuleManager < ModuleSet

	require 'msf/core/payload_set'

	include Framework::Offspring

	def initialize()
		self.module_paths         = []
		self.module_history       = {}
		self.module_history_mtime = {}
		self.module_sets          = {}

		MODULE_TYPES.each { |type|
			case type
				when MODULE_PAYLOAD
					instance = PayloadSet.new(self)
				else
					instance = ModuleSet.new(type)
			end

			self.module_sets[type] = instance

			# Set the module set's framework reference
			instance.framework = self.framework
		}

		super
	end

	#
	# Accessors by module type
	#

	# Returns the set of loaded encoder module classes
	def encoders
		return module_sets[MODULE_ENCODER]
	end

	# Returns the set of loaded exploit module classes
	def exploits
		return module_sets[MODULE_EXPLOIT]
	end

	# Returns the set of loaded nop module classes
	def nops
		return module_sets[MODULE_NOP]
	end

	# Returns the set of loaded payload module classes
	def payloads
		return module_sets[MODULE_PAYLOAD]
	end

	# Returns the set of loaded recon module classes
	def recon
		return module_sets[MODULE_RECON]
	end

	#
	# Module path management
	#

	# Adds a path to be searched for new modules
	def add_module_path(path)
		path.sub!(/#{File::SEPARATOR}$/, '')

		module_paths << path

		load_modules(path)
	end

	# Removes a path from which to search for modules
	def remove_module_path(path)
		module_paths.delete(path)
	end

protected

	# Load all of the modules from the supplied module path (independent of
	# module type)
	def load_modules(path)
		loaded = {}
		recalc = {}

		Find.find(path) { |file|

			# If the file doesn't end in the expected extension...
			next if (!file.match(/\.rb$/))

			# If the file on disk hasn't changed with what we have stored in the
			# cache, then there's no sense in loading it
			if (!has_module_file_changed?(file))
				dlog("Cached module from file #{file} has not changed.", 'core', 
					LEV_1)
			end

			# Substitute the base path
			path_base = file.sub(path + File::SEPARATOR, '')

			# Derive the name from the path with the exclusion of the .rb
			name = path_base.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

			# Chop off the file name
			path_base.sub!(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

			# Extract the module's namespace from its path
			mod  = mod_from_name(path_base)
			type = path_base.match(/^(.+?)#{File::SEPARATOR}+?/)[1].sub(/s$/, '')

			# Get the module and grab the current number of constants
			old_constants = mod.constants

			# Load the file
			begin
				if (!load(file))
					elog("Failed to load from file #{file}.")
					next
				end
			rescue LoadError
				elog("LoadError: #{$!}.")
				next
			end

			added = mod.constants - old_constants

			if (added.length > 1)
				elog("Loaded file contained more than one class (#{file}).")
				next
			end

			# If nothing was added, check to see if there's anything
			# in the cache
			if (added.empty?)
				if (module_history[file])
					added = module_history[file]
				else
					elog("Loaded #{file} but no classes were added.")
					next
				end
			else
				added = mod.const_get(added[0])
			end

			ilog("Loaded #{type} module #{added} from #{file}.", 'core', LEV_1)

			# Do some processing on the loaded module to get it into the
			# right associations
			on_module_load(added, type, name)

			# Set this module type as needing recalculation
			recalc[type] = true

			# Append the added module to the hash of file->module
			loaded[file] = added
		}

		# Cache the loaded file mtimes
		loaded.each_key {|file|
			module_history_mtime[file] = File.new(file).mtime
		}

		# Cache the loaded file module associations
		module_history.update(loaded)

		# Perform any required recalculations for the individual module types
		# that actually had load changes
		recalc.each_key { |key|
			module_sets[key].recalculate
		}

		return loaded.values
	end

	# Checks to see if the supplied file has changed (if it's even in the
	# cache)
	def has_module_file_changed?(file)
		return (module_history_mtime[file] != File.new(file).mtime)
	end

	# Returns the module object that is associated with the supplied module
	# name
	def mod_from_name(name)
		obj = Msf

		name.split(File::SEPARATOR).each { |m|
			# Up-case the first letter and any prefixed by _
			m.gsub!(/^[a-z]/) { |s| s.upcase }
			m.gsub!(/(_[a-z])/) { |s| s[1..1].upcase }

			begin
				obj = obj.const_get(m)
			rescue NameError
				obj = obj.const_set(m, ::Module.new)
			end
		}

		return obj
	end

	# Called when a module is initially loaded such that it can be
	# categorized accordingly
	def on_module_load(mod, type, name)
		# Payload modules require custom loading as the individual files
		# may not directly contain a logical payload that a user would 
		# reference, such as would be the case with a payload stager or 
		# stage.  As such, when payload modules are loaded they are handed
		# off to a special payload set.  The payload set, in turn, will
		# automatically create all the permutations after all the payload
		# modules have been loaded.
		if (type != MODULE_PAYLOAD)
			# Add the module class to the list of modules and add it to the
			# type separated set of module classes
			add_module(mod, name)
		end

		module_sets[type].add_module(mod, name)
	end

	attr_accessor :modules, :module_sets
	attr_accessor :module_paths
	attr_accessor :module_history, :module_history_mtime

end

end
