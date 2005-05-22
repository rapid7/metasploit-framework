require 'find'
require 'Msf/Core'

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
	def initialize(type)
		self.module_type       = type
		self.full_names        = {}
		self.ambiguous_names   = {}

		# Hashes that convey the supported architectures and platforms for a
		# given module
		self.mod_arch_hash     = {}
		self.mod_platform_hash = {}
	end

	# Create an instance of the supplied module by its name
	def create(name)
		# If the supplied name is known-ambiguous, prevent its creation
		if (ambiguous_names[name])
			raise(NameError.new("The supplied module name is ambiguous", name), 
				caller)
		end

		# If not by short name, then by full name, or so sayeth the spider
		if ((klass = self[name]) == nil)
			klass = full_names[name]
		end

		# Otherwise, try to create it
		return (klass) ? klass.new : nil
	end

	# Enumerates each module class in the set
	def each_module(opts = {}, &block)
		each_value { |mod|
			# Filter out incompatible architectures
			if (opts['arch'])
				if (!mod_arch_hash[mod])
					mod_arch_hash[mod] = mod.new.arch
				end

				next if (mod_arch_hash[mod].include?(opts['arch']) == false)
			end		

			# Filter out incompatible platforms
			if (opts['platform'])
				if (!mod_platform_hash[mod])
					mod_platform_hash[mod] = mod.new.platform
				end

				next if (mod_platform_hash[mod].include?(opts['platform']) == false)
			end

			block.call(mod)
		}
	end

	# Adds a module with a supplied short name, full name, and associated
	# module class
	def add_module(short_name, full_name, module_class)
		if (self[short_name])
			ambiguous_names << short_name
		else
			self[short_name] = module_class
		end

		full_names[full_name] = module_class
	end

	attr_reader   :module_type, :full_names

protected

	attr_writer   :module_type, :full_names
	attr_accessor :ambiguous_names
	attr_accessor :mod_arch_hash, :mod_platform_hash

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
class ModuleManager < Array

	def initialize()
		self.module_paths         = []
		self.module_history       = {}
		self.module_history_mtime = {}
		self.modules_by_type      = {}
		self.modules              = []

		MODULE_TYPES.each { |type|
			self.modules_by_type[type] = ModuleSet.new(type)
		}
	end

	#
	# Accessors by module type
	#

	# Returns the set of loaded encoder module classes
	def encoders
		return modules_by_type[MODULE_ENCODER]
	end

	# Returns the set of loaded exploit module classes
	def exploits
		return modules_by_type[MODULE_EXPLOIT]
	end

	# Returns the set of loaded nop module classes
	def nops
		return modules_by_type[MODULE_NOPS]
	end

	# Returns the set of loaded payload module classes
	def payloads
		return modules_by_type[MODULE_PAYLOAD]
	end

	# Returns the set of loaded recon module classes
	def recon
		return modules_by_type[MODULE_RECON]
	end

	#
	# Module path management
	#

	# Adds a path to be searched for new modules
	def add_module_path(path)
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

			# Extract the type of module
			md = path_base.match(/^(.*?)#{File::SEPARATOR}/)

			next if (!md)

			# Use the de-pluralized version of the type as necessary
			type = md[1].sub(/s$/, '').downcase

			# Extract the module namespace
			md = path_base.match(/^(.*)#{File::SEPARATOR}(.*?)$/)

			next if (!md)

			# Prefix Msf to the namespace
			namespace = 'Msf::' + md[1].sub(File::SEPARATOR, "::")

			dlog("Loading #{type} module from #{path_base}...", 'core', LEV_1)

			# Get the module and grab the current number of constants
			old_constants = []
			mod = mod_from_name(namespace)	

			if (mod)
				old_constants = mod.constants
			end

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

			# Incase we hadn't gotten the module yet...
			mod = mod_from_name(namespace)	

			if (!mod)
				elog("Load did not create expected namespace #{namespace}.")
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
			on_module_load(type, added)

			# Append the added module to the hash of file->module
			loaded[file] = added
		}

		# Cache the loaded file mtimes
		loaded.each_key {|file|
			module_history_mtime[file] = File.new(file).mtime
		}

		# Cache the loaded file module associations
		module_history.update(loaded)

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
		obj = Object

		name.split('::').each { |m|
			begin
				obj = obj.const_get(m)
			rescue NameError
				obj = nil
				break
			end
		}

		return obj
	end

	# Called when a module is initially loaded such that it can be
	# categorized accordingly
	def on_module_load(type, mod)
		# Extract the module name information
		mod_full_name = mod.to_s.gsub('::', '_')
		mod_full_name.sub!(/^Msf_(.*?)_/, '')

		mod_short_name = mod_full_name

		if ((md = mod_full_name.match(/_(.*)$/)))
			mod_short_name = md[1]
		end

		# Add the module class to the list of modules and add it to the
		# type separated set of module classes
		modules << mod
		modules_by_type[type].add_module(mod_short_name, mod_full_name, mod)
	end

	attr_accessor :modules, :modules_by_type
	attr_accessor :module_paths
	attr_accessor :module_history, :module_history_mtime

end

end
