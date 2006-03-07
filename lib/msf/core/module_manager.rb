require 'find'
require 'msf/core'

module Msf

#
# Define used for a place-holder module that is used to indicate that the
# module has not yet been demand-loaded.
#
SymbolicModule = "__SYMBOLIC__"

###
#
# A module set contains zero or more named module classes of an arbitrary
# type.
#
###
class ModuleSet < Hash

	include Framework::Offspring

	#
	# Initializes a module set that will contain modules of a specific type and
	# expose the mechanism necessary to create instances of them.
	#
	def initialize(type = nil)
		self.module_type       = type

		# Hashes that convey the supported architectures and platforms for a
		# given module
		self.mod_arch_hash     = {}
		self.mod_platform_hash = {}
		self.mod_sorted        = nil
		self.mod_ranked        = nil
		self.mod_extensions    = []
		self.mod_ambiguous     = {}
	end

	#
	# Wrapper that detects if a symbolic module is in use.  If it is, it
	# creates an instance to demand load the module and then returns the
	# now-loaded class afterwords.
	#
	def [](name)
		if (get_hash_val(name) == SymbolicModule)
			create(name)
		end

		get_hash_val(name)
	end

	#
	# Returns the hash value associated with the supplied module name without
	# throwing an exception.
	#
	def get_hash_val(name)
		begin
			return self.fetch(name)
		rescue IndexError
			return nil
		end
	end

	#
	# Create an instance of the supplied module by its name
	#
	def create(name)
		if (mod_ambiguous[name])
			raise Rex::AmbiguousArgumentError.new(name), 
				"The module name #{name} is ambiguous.", caller
		end

		klass    = get_hash_val(name)
		instance = nil

		# If there is no module associated with this class, then try to demand
		# load it.
		if (klass.nil? or klass == SymbolicModule)
			# If we are the root module set, then we need to try each module
			# type's demand loading until we find one that works for us.
			if (module_type.nil?)
				MODULE_TYPES.each { |type|
					framework.modules.demand_load_module(type + '/' + name)
				}
			else
				framework.modules.demand_load_module(module_type + '/' + name)
			end

			klass = get_hash_val(name)
		end

		# If the klass is valid for this name, try to create it
		if (klass and klass != SymbolicModule)
			instance = klass.new
		end

		# Notify any general subscribers of the creation event
		if (instance)
			self.framework.events.on_module_created(instance)
		end

		return instance
	end

	#
	# Checks to see if the supplied module name is valid.
	#
	def valid?(name)
		# If we're using cache, then we need to pre-create an instance of this.
		create(name) if (using_cache)

		(self[name]) ? true : false
	end

	#
	# Enumerates each module class in the set.
	#
	def each_module(opts = {}, &block)
		demand_load_modules

		mod_sorted = self.sort if (mod_sorted == nil)
		
		each_module_list(mod_sorted, opts, &block)
	end

	#
	# Enumerates each module class in the set based on their relative ranking
	# to one another.  Modules that are ranked higher are shown first.
	#
	def each_module_ranked(opts = {}, &block)
		demand_load_modules

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
	# Dummy placeholder to relcalculate aliases and other fun things.
	#
	def recalculate
	end

	attr_reader   :module_type

	#
	# Whether or not recalculations should be postponed.  This is used from the
	# context of the each_module_list handler in order to prevent the demand
	# loader from calling recalc for each module if it's possible that more
	# than one module may be loaded.  This field is not initialized until used.
	#
	attr_accessor :postpone_recalc

protected

	#
	# Load all modules that are marked as being symbolic.
	#
	def demand_load_modules
		# Pre-scan the module list for any symbolic modules
		self.each_pair { |name, mod|
			if (mod == SymbolicModule)
				self.postpone_recalc = true

				mod = create(name)

				next if (mod.nil?)
			end
		}

		# If we found any symbolic modules, then recalculate.
		if (self.postpone_recalc)
			self.postpone_recalc = false

			recalculate
		end
	end

	#
	# Enumerates the modules in the supplied array with possible limiting
	# factors.
	#
	def each_module_list(ary, opts, &block)
		ary.each { |entry|
			name, mod = entry

			# Skip any lingering symbolic modules.
			next if (mod == SymbolicModule)

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
			a_rank = a[1].const_defined?('Rank') ? a[1].const_get('Rank') : NormalRanking
			b_rank = b[1].const_defined?('Rank') ? b[1].const_get('Rank') : NormalRanking

			# Compare their relevant rankings.  Since we want highest to lowest,
			# we compare b_rank to a_rank in terms of higher/lower precedence
			b_rank <=> a_rank	
		}
	end

	#
	# Adds a module with a the supplied name.
	#
	def add_module(module_class, name, modinfo = nil)
		# Duplicate the module class so that we can operate on a
		# framework-specific copy of it.
		dup = module_class.dup

		# Set the module's name so that it can be referenced when
		# instances are created.
		dup.framework = framework
		dup.refname   = name
		dup.file_path = ((modinfo and modinfo['files']) ? modinfo['files'][0] : nil)
		dup.orig_cls  = module_class

		if (get_hash_val(name) and get_hash_val(name) != SymbolicModule)
			mod_ambiguous[name] = true

			wlog("The module #{dup.refname} is ambiguous with #{self[name].refname}.")
		else
			self[name] = dup
		end

		# Check to see if we should update info
		noup = true if (modinfo and modinfo['noup'])

		# Add this module to the module cache for this type
		framework.modules.cache_module(dup) if (noup != true)
	
		# Invalidate the sorted array
		invalidate_sorted_cache

		# Return the duplicated instance for use
		dup
	end

	#
	# Invalidates the sorted and ranked module caches.
	#
	def invalidate_sorted_cache
		mod_sorted = nil
		mod_ranked = nil
	end

	attr_writer   :module_type
	attr_accessor :mod_arch_hash, :mod_platform_hash
	attr_accessor :mod_sorted, :mod_ranked
	attr_accessor :mod_extensions, :mod_ambiguous

end

###
#
# Upper management decided to throw in some middle management
# because the modules were getting out of hand.  This bad boy
# takes care of the work of managing the interaction with 
# modules in terms of loading and instantiation.
#
# TODO:
#
#   - add unload support
#
###
class ModuleManager < ModuleSet

	require 'msf/core/payload_set'

	include Framework::Offspring

	#
	# Initializes an instance of the overall module manager using the supplied
	# framework instance.
	#
	def initialize(framework)
		self.module_paths         = []
		self.module_history       = {}
		self.module_history_mtime = {}
		self.module_sets          = {}
		self.framework            = framework

		MODULE_TYPES.each { |type|
			case type
				when MODULE_PAYLOAD
					instance = PayloadSet.new(self)
				else
					instance = ModuleSet.new(type)
			end

			self.module_sets[type] = instance

			# Set the module set's framework reference
			instance.framework = framework
		}

		super(nil)
	end

	#
	# Creates a module using the supplied name.
	#
	def create(name)
		# Check to see if it has a module type prefix.  If it does,
		# try to load it from the specific module set for that type.
		if (md = name.match(/^(#{MODULE_TYPES.join('|')})\/(.*)$/))
			module_sets[md[1]].create(md[2])
		# Otherwise, just try to load it by name.
		else
			super
		end
	end

	#
	# Accessors by module type
	#

	#
	# Returns the set of loaded encoder module classes.
	#
	def encoders
		return module_sets[MODULE_ENCODER]
	end

	#
	# Returns the set of loaded exploit module classes.
	#
	def exploits
		return module_sets[MODULE_EXPLOIT]
	end

	#
	# Returns the set of loaded nop module classes.
	#
	def nops
		return module_sets[MODULE_NOP]
	end

	#
	# Returns the set of loaded payload module classes.
	#
	def payloads
		return module_sets[MODULE_PAYLOAD]
	end

	#
	# Returns the set of loaded auxiliary module classes.
	#
	def auxiliary
		return module_sets[MODULE_AUX]
	end

	##
	#
	# Module cache management to support demand loaded modules.
	#
	##

	#
	# Sets the path that the module cache information is loaded from and
	# synchronized with.  This method should be called prior to loading any
	# modules in order to take advantage of caching information.
	#
	def set_module_cache_file(file_path)
		@modcache_file = file_path
		@modcache      = Rex::Parser::Ini.new

		begin
			@modcache.from_file(@modcache_file)
		rescue Errno::ENOENT
			@modcache_invalidated = true
		end

		# Initialize the standard groups
		@modcache.add_group('FileModificationTimes', false)
		@modcache.add_group('ModuleTypeCounts', false)

		MODULE_TYPES.each { |type|
			@modcache.add_group(type, false)

			@modcache[type].each_key { |name|
				fullname = type + '/' + name

				# Make sure the files associated with this module exist.  If it
				# doesn't, then we don't create a symbolic module for it.  This is
				# to ensure that module counts are accurately reflected after a
				# module is removed or moved.
				next if (@modcache.group?(fullname) == false)
				next if (@modcache[fullname]['FileNames'].nil?)

				begin
					@modcache[fullname]['FileNames'].split(',').each { |f|
						File::Stat.new(f)
					}
				rescue Errno::ENOENT
					dlog("File requirement does not exist for #{fullname}", 'core', 
						LEV_1);
					next
				end

				module_sets[type][name] = SymbolicModule
			}
		}
	end

	#
	# Returns true if the module cache is currently being used.
	#
	def using_cache
		(@modcache_invalidated != true)
	end

	#
	# Returns the cached module counts by type if the cache is being used.
	#
	def cached_counts
		if (using_cache and @modcache.group?('ModuleTypeCounts'))
			if (@cached_counts.nil?)
				@cached_counts = {}
	
				@modcache['ModuleTypeCounts'].each_pair { |type, count|
					@cached_counts[type] = count.to_i
				}
			end

			return @cached_counts
		end

		return nil
	end

	#
	# Persists the current contents of the module cache to disk.
	#
	def save_module_cache
		if (@modcache)
			if (@modcache.group?('ModuleTypeCounts'))
				@modcache['ModuleTypeCounts'].clear

				MODULE_TYPES.each { |type|
					@modcache['ModuleTypeCounts'][type] = module_sets[type].length.to_s
				}
			end

			@modcache.to_file(@modcache_file)
		end
	end

	#
	# Checks to make sure the cache state is okay.  If it's not, the cache is
	# cleared and all modules are forced to be loaded.  If the cached mtime for
	# the file is the same as the current mtime, then we don't load it until
	# it's needed on demand.
	#
	def check_cache(file)
		# If the module cache has been invalidated, then we return false to
		# indicate that we should go ahead and load the file now.
		return false if (@modcache_invalidated)

		if (@modcache and @modcache.group?('FileModificationTimes'))
			no_exist = false

			begin
				curr_mtime = File::Stat.new(file).mtime
			rescue Errno::ENOENT
				no_exist = true
			end

			if (no_exist or 
			    @modcache['FileModificationTimes'][file].nil? or
			    @modcache['FileModificationTimes'][file].to_s != curr_mtime.to_i.to_s)
				raise ModuleCacheInvalidated, "File #{file} has a new mtime or did not exist"
			end
		end

		return true
	end

	#
	# Invalidates the current cache.
	#
	def invalidate_cache
		@modcache_invalidated = true

		# Clear the module cache.
		if (@modcache)
			@modcache['FileModificationTimes'].clear
			@modcache['ModuleTypeCounts'].clear
			
			MODULE_TYPES.each { |type|
				@modcache[type].clear
			}
		end
	end

	#
	# Synchronizes the module cache information 
	#
	def update_module_cache_info(fullname, modinfo)
		return if (modinfo and modinfo['noup'] == true)

		if (@modcache)
			if (fullname)
				@modcache.add_group(fullname)
				@modcache[fullname].clear
				@modcache[fullname]['FileNames'] = modinfo['files'].join(',') 
				@modcache[fullname]['FilePaths'] = modinfo['paths'].join(',') 
				@modcache[fullname]['Type']      = modinfo['type']
			end

			modinfo['files'].each { |p|
				begin
					@modcache['FileModificationTimes'][p] = File::Stat.new(p).mtime.to_i.to_s
				rescue Errno::ENOENT
				end
			}
		end
	end

	#
	# Caches this module under a specific module type and name
	#
	def cache_module(mod)
		@modcache[mod.type][mod.refname] = 1
	end

	##
	#
	# Module path management
	#
	##

	#
	# Adds a path to be searched for new modules.
	#
	def add_module_path(path)
		path.sub!(/#{File::SEPARATOR}$/, '')

		# Make sure the path is a valid directory before we try to rock the
		# house
		if (File.directory?(path) == false)
			raise NameError, "The path supplied is not a valid directory.",
				caller
		end

		module_paths << path

		begin
			counts = load_modules(path)
		rescue ModuleCacheInvalidated
			invalidate_cache

			# Re-load all the modules now that the cache has been invalidated
			module_paths.each { |p|
				counts = load_modules(p, true)
			}
		end

		# Synchronize the module cache if the module cache is not being used.
		save_module_cache if (!using_cache)

		return counts
	end

	#
	# Removes a path from which to search for modules.
	#
	def remove_module_path(path)
		module_paths.delete(path)
	end

	def register_type_extension(type, ext)
	end

	#
	# Reloads the module specified in mod.  This can either be an instance of a
	# module or a module class.
	#
	def reload_module(mod)
		refname = mod.refname
		ds      = mod.datastore.dup

		dlog("Reloading module #{refname}...", 'core')

		if (mod.file_path)
			begin
				if (!load(mod.file_path))
					elog("Failed to load module from #{mod.file_path}")
					return nil
				end

			rescue
				elog("Failed to reload module #{mod} from #{mod.file_path}: #{$!}")
				raise $!
			end
		end

		# Remove the original reference to this module
		self.delete(mod.refname)

		# Indicate that the module is being loaded again so that any necessary
		# steps can be taken to extend it properly.
		on_module_load(mod.orig_cls, mod.type, refname, {
			'files' => [ mod.file_path ],
			'noup'  => true})

		# Create a new instance of the module
		if (mod = create(refname))
			mod.datastore.update(ds)
		else
			elog("Failed to create instance of #{refname} after reload.", 'core')
		end

		mod
	end

	#
	# Overrides the module set method for adding a module so that some extra
	# steps can be taken to subscribe the module and notify the event
	# dispatcher.
	#
	def add_module(mod, name, file_paths)
		# Call the module set implementation of add_module
		dup = super

		# If the module cache is not being used, update the cache with
		# information about the files that are associated with this module.
		if (!using_cache)
			update_module_cache_info(dup.fullname, file_paths)
		end

		# Automatically subscribe a wrapper around this module to the necessary
		# event providers based on whatever events it wishes to receive.  We
		# only do this if we are the module manager instance, as individual
		# module sets need not subscribe.
		auto_subscribe_module(dup)

		# Notify the framework that a module was loaded
		framework.events.on_module_load(name, dup)
	end

	#
	# Loads the files associated with a module and recalculates module
	# associations.
	#
	def demand_load_module(fullname)
		dlog("Demand loading module #{fullname}.", 'core', LEV_1)

		return nil if (@modcache.group?(fullname) == false)
		return nil if (@modcache[fullname]['FileNames'].nil?)
		return nil if (@modcache[fullname]['FilePaths'].nil?)

		type  = fullname.split(/\//)[0]
		files = @modcache[fullname]['FileNames'].split(',')
		paths = @modcache[fullname]['FilePaths'].split(',')

		files.each_with_index { |file, idx|
			dlog("Loading from file #{file}", 'core', LEV_2)

			load_module_from_file(paths[idx], file, nil, nil, nil, true)
		}

		if (module_sets[type].postpone_recalc != true)
			module_sets[type].recalculate
		end
	end

protected

	#
	# Load all of the modules from the supplied module path (independent of
	# module type).
	#
	def load_modules(path, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		# Try to load modules from all the files in the supplied path
		Find.find(path) { |file|
			# Skip unit test files
			next if (file =~ /rb\.ut\.rb$/)

			# Skip test-suite files
			next if (file =~ /rb\.ts\.rb$/)

			begin
				load_module_from_file(path, file, loaded, recalc, counts, demand)
			rescue NameError
				# If we get a name error, it's possible that this module depends
				# on another one that we haven't loaded yet.  Let's postpone
				# the load operation for now so that we can resolve all 
				# dependencies.  This is pretty much a hack.
				delay[file] = $!
			end
		}

		# Keep processing all delayed module loads until we've gotten
		# all the dependencies resolved or until we just suck.
		while (ks == true)
			ks = false

			delay.each_key { |file|
				begin
					# Load the module from the file...
					load_module_from_file(path, file, loaded, recalc, counts, demand)

					# Remove this file path from the list of delay load files
					# because if we get here it means all when swell...maybe.
					delay.delete(file)

					# Keep scanning since we just successfully loaded a delay load
					# module.
					ks = true
				# Trap the name error and flag this file path as still needing to
				# be delay loaded.
				rescue NameError
					delay[file] = $!	
				end
			}
		end

		# Log all modules that failed to load due to problems
		delay.each_pair { |file, err|
			elog("Failed to load module from #{file}: #{err}")
		}

		# Perform any required recalculations for the individual module types
		# that actually had load changes
		recalc.each_key { |key|
			module_sets[key].recalculate
		}

		# Return per-module loaded counts
		return counts
	end

	#
	# Loads a module from the supplied file.
	#
	def load_module_from_file(path, file, loaded, recalc, counts, demand = false)
		# If the file doesn't end in the expected extension...
		return nil if (!file.match(/\.rb$/))

		# If the file on disk hasn't changed with what we have stored in the
		# cache, then there's no sense in loading it
		if (!has_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', 
				LEV_2)
			return false
		end

		# Substitute the base path
		path_base = file.sub(path + File::SEPARATOR, '')

		# Derive the name from the path with the exclusion of the .rb
		name = path_base.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		path_base.sub!(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		# Extract the module's namespace from its path
		mod = mod_from_name(path_base)

		if (m = path_base.match(/^(.+?)#{File::SEPARATOR}+?/)) 
			type = m[1]
		else
			type = path_base
		end
		
		type.sub!(/s$/, '')

		#
		# If the cached version of the file is still okay, then we just return
		# as we don't need to load it yet.  We do not currently support demand
		# loading of encoders and nops due to some API assumptions
		# (EncodedPayload assumes it can enumerate through all encoders/nops).
		#
		# FIXME: support demand loading of encoders/nops
		#
		if ((demand == false) and
		    (check_cache(file)) and
		    ([ MODULE_ENCODER, MODULE_NOP ].include?(type) == false))
			return false 
		end

		# Synchronize the modification time for this file.
		update_module_cache_info(nil, {
			'paths' => [ path ],
			'files' => [ file ],
			'type'  => type}) if (!using_cache)	

		# Get the module and grab the current number of constants
		old_constants = mod.constants

		# Load the file like it aint no thang
		begin
			if (!load(file))
				elog("Failed to load from file #{file}.")
				return false
			end
		rescue NameError
			added = mod.constants - old_constants

			# Super hack.  If a constant was added (which will represent the
			# module), then we need to remove it so that our logic for
			# detecting new classes in the future will work when we
			# subsequently try to reload it.
			r = mod.module_eval { remove_const(added[0]) } if (added[0])

			# Re-raise the name error so that the caller catches it and adds this
			# file path to the list of files that are to be delay loaded.
			raise NameError, $!
		rescue LoadError
			elog("LoadError: #{$!}.")
			return false
		end

		added = mod.constants - old_constants

		if (added.length > 1)
			elog("Loaded file contained more than one class (#{file}).")
			return false
		end

		# If nothing was added, check to see if there's anything
		# in the cache
		if (added.empty?)
			if (module_history[file])
				added = module_history[file]
			else
				elog("Loaded #{file} but no classes were added.")
				return false
			end
		else
			added = mod.const_get(added[0])
		end

		# If the module indicates that it is not usable on this system, then we 
		# will not try to use it.
		usable = false

		begin
			usable = added.is_usable
		# If no method is defined, assume that this module is usable.
		rescue NoMethodError
			usable = true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end
			
		if (usable == false)
			ilog("Skipping module in #{file} because is_usable returned false.", 
				'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{file}.", 'core', LEV_2)

		# Do some processing on the loaded module to get it into the
		# right associations
		on_module_load(added, type, name, {
			'files' => [ file ],
			'paths' => [ path ],
			'type'  => type })

		# Set this module type as needing recalculation
		recalc[type] = true if (recalc)

		# Append the added module to the hash of file->module
		loaded[file] = added if (loaded)
	
		# Track module load history for future reference
		module_history[file]       = added
		module_history_mtime[file] = File::Stat.new(file).mtime.to_i

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
	end

	#
	# Checks to see if the supplied file has changed (if it's even in the
	# cache).
	#
	def has_module_file_changed?(file)
		begin
			return (module_history_mtime[file] != File::Stat.new(file).mtime.to_i)
		rescue Errno::ENOENT
			return true
		end
	end

	#
	# Returns the module object that is associated with the supplied module
	# name.
	#
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

	#
	# Called when a module is initially loaded such that it can be
	# categorized accordingly.
	#
	def on_module_load(mod, type, name, modinfo)
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
			add_module(mod, name, modinfo)
		end

		module_sets[type].add_module(mod, name, modinfo)
	end

	#
	# This method automatically subscribes a module to whatever event providers
	# it wishes to monitor.  This can be used to allow modules to automatically
	# execute or perform other tasks when certain events occur.  For instance,
	# when a new host is detected, other aux modules may wish to run such
	# that they can collect more information about the host that was detected.
	#
	def auto_subscribe_module(mod)
		# If auto-subscribe has been disabled
		if (framework.datastore['DisableAutoSubscribe'] and
		    framework.datastore['DisableAutoSubscribe'] =~ /^(y|1|t)/)
			return
		end

		# If auto-subscription is enabled (which it is by default), figure out
		# if it subscribes to any particular interfaces.
		inst = nil

		#
		# Exploit event subscriber check
		#
		if (mod.include?(ExploitEvent) == true)
			framework.events.add_exploit_subscriber((inst) ? inst : (inst = mod.new))
		end

		#
		# Session event subscriber check
		#
		if (mod.include?(SessionEvent) == true)
			framework.events.add_session_subscriber((inst) ? inst : (inst = mod.new))
		end
	end

	attr_accessor :modules, :module_sets # :nodoc:
	attr_accessor :module_paths # :nodoc:
	attr_accessor :module_history, :module_history_mtime # :nodoc:

end

end
