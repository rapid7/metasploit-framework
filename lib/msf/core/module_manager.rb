# -*- coding: binary -*-
require 'msf/core'
require 'fastlib'
require 'pathname'

module Msf

#
# Define used for a place-holder module that is used to indicate that the
# module has not yet been demand-loaded. Soon to go away.
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
		fetch(name) if has_key?(name)
	end

	#
	# Create an instance of the supplied module by its name
	#
	def create(name)

		klass    = get_hash_val(name)
		instance = nil

		# If there is no module associated with this class, then try to demand
		# load it.
		if (klass.nil? or klass == SymbolicModule)
			# If we are the root module set, then we need to try each module
			# type's demand loading until we find one that works for us.
			if (module_type.nil?)
				MODULE_TYPES.each { |type|
					framework.modules.demand_load_module(type, name)
				}
			else
				framework.modules.demand_load_module(module_type, name)
			end

			recalculate

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
		create(name)
		(self[name]) ? true : false
	end

	#
	# Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
	#    "can't add a new key into hash during iteration"
	#
	def each(&block)
		list = []
		self.keys.sort.each do |sidx|
			list << [sidx, self[sidx]]
		end
		list.each(&block)
	end

	#
	# Enumerates each module class in the set.
	#
	def each_module(opts = {}, &block)
		demand_load_modules

		self.mod_sorted = self.sort

		each_module_list(mod_sorted, opts, &block)
	end

	#
	# Enumerates each module class in the set based on their relative ranking
	# to one another.  Modules that are ranked higher are shown first.
	#
	def each_module_ranked(opts = {}, &block)
		demand_load_modules

		self.mod_ranked = rank_modules

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

	#
	# Gives the module set an opportunity to handle a module reload event
	#
	def on_module_reload(mod)
	end

	#
	# Forces all modules in this set to be loaded.
	#
	def force_load_set
		each_module { |name, mod| }
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
		self.mod_ranked = self.sort { |a, b|
			a_name, a_mod = a
			b_name, b_mod = b

			# Dynamically loads the module if needed
			a_mod = create(a_name) if a_mod == SymbolicModule
			b_mod = create(b_name) if b_mod == SymbolicModule

			# Extract the ranking between the two modules
			a_rank = a_mod.const_defined?('Rank') ? a_mod.const_get('Rank') : NormalRanking
			b_rank = b_mod.const_defined?('Rank') ? b_mod.const_get('Rank') : NormalRanking

			# Compare their relevant rankings.  Since we want highest to lowest,
			# we compare b_rank to a_rank in terms of higher/lower precedence
			b_rank <=> a_rank
		}
	end

	#
	# Adds a module with a the supplied name.
	#
	def add_module(mod, name, modinfo = nil)


		# Set the module's name so that it can be referenced when
		# instances are created.
		mod.framework = framework
		mod.refname   = name
		mod.file_path = ((modinfo and modinfo['files']) ? modinfo['files'][0] : nil)
		mod.orig_cls  = mod

		if (get_hash_val(name) and get_hash_val(name) != SymbolicModule)
			mod_ambiguous[name] = true

			wlog("The module #{mod.refname} is ambiguous with #{self[name].refname}.")
		else
			self[name] = mod
		end

		mod
	end

	attr_writer   :module_type
	attr_accessor :mod_arch_hash, :mod_platform_hash
	attr_accessor :mod_sorted, :mod_ranked
	attr_accessor :mod_extensions, :mod_ambiguous
	attr_accessor :module_history

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
	# framework instance. The types parameter can be used to only load specific
	# module types on initialization
	#
	def initialize(framework,types=MODULE_TYPES)
		self.module_paths         = []
		self.module_sets          = {}
		self.module_failed        = {}
		self.enabled_types        = {}
		self.framework            = framework
		self.cache                = {}

		types.each { |type|
			init_module_set(type)
		}

		super(nil)
	end

	def init_module_set(type)
		self.enabled_types[type] = true
		case type
		when MODULE_PAYLOAD
			instance = PayloadSet.new(self)
		else
			instance = ModuleSet.new(type)
		end

		self.module_sets[type] = instance

		# Set the module set's framework reference
		instance.framework = self.framework
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
	# Returns all of the modules of the specified type
	#
	def module_set(type)
		module_sets[type]
	end

	#
	# Returns the set of loaded encoder module classes.
	#
	def encoders
		module_set(MODULE_ENCODER)
	end


	#
	# Returns the set of loaded exploit module classes.
	#
	def exploits
		module_set(MODULE_EXPLOIT)
	end

	#
	# Returns the set of loaded nop module classes.
	#
	def nops
		module_set(MODULE_NOP)
	end

	#
	# Returns the set of loaded payload module classes.
	#
	def payloads
		module_set(MODULE_PAYLOAD)
	end

	#
	# Returns the set of loaded auxiliary module classes.
	#
	def auxiliary
		module_set(MODULE_AUX)
	end

	#
	# Returns the set of loaded auxiliary module classes.
	#
	def post
		module_set(MODULE_POST)
	end

	#
	# Returns the set of modules that failed to load.
	#
	def failed
		return module_failed
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
		npaths = []
		
		if path =~ /\.fastlib$/
			unless ::File.exist?(path)
				raise RuntimeError, "The path supplied does not exist", caller
			end
			npaths << ::File.expand_path(path)
		else
			path.sub!(/#{File::SEPARATOR}$/, '')

			# Make the path completely canonical
			path = Pathname.new(File.expand_path(path))

			# Make sure the path is a valid directory
			unless path.directory?
				raise RuntimeError, "The path supplied is not a valid directory.", caller
			end

			# Now that we've confirmed it exists, get the full, cononical path
			path    = ::File.expand_path(path)
			npaths << path

			# Identify any fastlib archives inside of this path
			Dir["#{path}/**/*.fastlib"].each do |fp|
				npaths << fp
			end
		end

		# Update the module paths appropriately
		self.module_paths = (module_paths + npaths).flatten.uniq
	
		# Load all of the modules from the new paths
		counts = nil
		npaths.each { |d|
			counts = load_modules(d, false)
		}
		
		return counts
	end

	#
	# Removes a path from which to search for modules.
	#
	def remove_module_path(path)
		module_paths.delete(path)
		module_paths.delete(::File.expand_path(path))
	end

	def register_type_extension(type, ext)
	end

	#
	# Reloads modules from all module paths
	#
	def reload_modules

		self.module_history = {}
		self.clear

		self.enabled_types.each_key do |type|
			module_sets[type].clear
			init_module_set(type)
		end

		# The number of loaded modules in the following categories:
		# auxiliary/encoder/exploit/nop/payload/post
		count = 0
		module_paths.each do |path|
			mods = load_modules(path, true)
			mods.each_value {|c| count += c}
		end

		rebuild_cache

		count
	end

	#
	# Reloads the module specified in mod.  This can either be an instance of a
	# module or a module class.
	#
	def reload_module(mod)
		omod    = mod
		refname = mod.refname
		ds      = mod.datastore

		dlog("Reloading module #{refname}...", 'core')

		# Set the target file
		file = mod.file_path
		wrap = ::Module.new

		# Load the module into a new Module wrapper
		begin
			wrap.module_eval(load_module_source(file), file)
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[mod.file_path] = errmsg
					return false
				end
			end
		rescue ::Exception => e

			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to reload module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[mod.file_path] = errmsg
					return
				end
			end

			errmsg = "Failed to reload module from #{file}: #{e.class} #{e}"
			elog(errmsg)
			self.module_failed[mod.file_path] = errmsg
			return
		end

		added = nil
		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Reloaded file did not contain a valid module (#{file})."
			elog(errmsg)
			self.module_failed[mod.file_path] = errmsg
			return nil
		end

		self.module_failed.delete(mod.file_path)

		# Remove the original reference to this module
		self.delete(mod.refname)

		# Indicate that the module is being loaded again so that any necessary
		# steps can be taken to extend it properly.
		on_module_load(added, mod.type, refname, {
			'files' => [ mod.file_path ],
			'noup'  => true})

		# Create a new instance of the module
		if (mod = create(refname))
			mod.datastore.update(ds)
		else
			elog("Failed to create instance of #{refname} after reload.", 'core')
			# Return the old module instance to avoid a strace trace
			return omod
		end

		# Let the specific module sets have an opportunity to handle the fact
		# that this module was reloaded.
		module_sets[mod.type].on_module_reload(mod)

		# Rebuild the cache for just this module
		rebuild_cache(mod)

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

		# Automatically subscribe a wrapper around this module to the necessary
		# event providers based on whatever events it wishes to receive.  We
		# only do this if we are the module manager instance, as individual
		# module sets need not subscribe.
		auto_subscribe_module(dup)

		# Notify the framework that a module was loaded
		framework.events.on_module_load(name, dup)
	end

	#
	# Provide a list of the types of modules in the set
	#
	def module_types
		module_sets.keys.dup
	end

	#
	# Provide a list of module names of a specific type
	#
	def module_names(set)
		module_sets[set] ? module_sets[set].keys.dup : []
	end

	#
	# Read the module code from the file on disk
	#
	def load_module_source(file)
		::File.read(file, ::File.size(file))
	end

	#
	# Rebuild the cache for the module set
	#
	def rebuild_cache(mod = nil)
		return if not (framework.db and framework.db.migrated)
		if mod
			framework.db.update_module_details(mod)
		else
			framework.db.update_all_module_details
		end
		refresh_cache
	end

	#
	# Return a listing of all cached modules
	#
	def cache_entries
		return {} if not (framework.db and framework.db.migrated)
		res = {}
		::Mdm::ModuleDetail.find(:all).each do |m|
			res[m.file] = { :mtype => m.mtype, :refname => m.refname, :file => m.file, :mtime => m.mtime }
			unless module_set(m.mtype).has_key?(m.refname)
				module_set(m.mtype)[m.refname] = SymbolicModule
			end
		end
	
		res
	end

	#
	# Reset the module cache
	#
	def refresh_cache
		self.cache = cache_entries
	end

	def has_module_file_changed?(file)
		begin 
			cfile = self.cache[file] 
			return true if not cfile

			# Payloads can't be cached due to stage/stager matching
			return true if cfile[:mtype] == "payload"
			return cfile[:mtime].to_i != ::File.mtime(file).to_i
		rescue ::Errno::ENOENT
			return true
		end
	end

	def has_archive_file_changed?(arch, file)
		begin 		
			cfile = self.cache[file]
			return true if not cfile

			# Payloads can't be cached due to stage/stager matching
			return true if cfile[:mtype] == "payload"

			return cfile[:mtime].to_i != ::File.mtime(file).to_i
		rescue ::Errno::ENOENT
			return true
		end
	end

	def demand_load_module(mtype, mname)
		n = self.cache.keys.select { |k| 
			self.cache[k][:mtype]   == mtype and 
			self.cache[k][:refname] == mname 
		}.first

		return nil unless n
		m = self.cache[n]

		path = nil
		if m[:file] =~ /^(.*)\/#{m[:mtype]}s?\//
			path = $1
			load_module_from_file(path, m[:file], nil, nil, nil, true)
		else
			dlog("Could not demand load module #{mtype}/#{mname} (unknown base name in #{m[:file]})", 'core', LEV_2)
			nil
		end
	end

	attr_accessor :cache # :nodoc:

protected


	#
	# Load all of the modules from the supplied directory or archive
	#
	def load_modules(bpath, demand = false)
		( bpath =~ /\.fastlib$/ ) ?
			load_modules_from_archive(bpath, demand) :
			load_modules_from_directory(bpath, demand)
	end

	#
	# Load all of the modules from the supplied module path (independent of
	# module type).
	#
	def load_modules_from_directory(bpath, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		dbase  = ::Dir.new(bpath)
		dbase.entries.each do |ent|
			next if ent.downcase == '.svn'

			path  = ::File.join(bpath, ent)
			mtype = ent.gsub(/s$/, '')

			next if not ::File.directory?(path)
			next if not MODULE_TYPES.include?(mtype)
			next if not enabled_types[mtype]

			# Try to load modules from all the files in the supplied path
			Rex::Find.find(path) do |file|

				# Skip non-ruby files
				next if file[-3,3] != ".rb"

				# Skip unit test files
				next if (file =~ /rb\.(ut|ts)\.rb$/)

				# Skip files with a leading period
				next if file[0,1] == "."

				load_module_from_file(bpath, file, loaded, recalc, counts, demand)
			end
		end

		recalc.each_key do |mtype|
			module_set(mtype).recalculate		
		end

		# Return per-module loaded counts
		return counts
	end


	#
	# Load all of the modules from the supplied fastlib archive
	#
	def load_modules_from_archive(bpath, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		::FastLib.list(bpath).each do |ent|

			next if ent.index(".svn/")

			mtype, path = ent.split("/", 2)
			mtype.sub!(/s$/, '')

			next if not MODULE_TYPES.include?(mtype)
			next if not enabled_types[mtype]

			# Skip non-ruby files
			next if ent[-3,3] != ".rb"

			# Skip unit test files
			next if (ent =~ /rb\.(ut|ts)\.rb$/)

			# Skip files with a leading period
			next if ent[0,1] == "."

			load_module_from_archive(bpath, ent, loaded, recalc, counts, demand)
		end

		recalc.each_key do |mtype|
			module_set(mtype).recalculate		
		end

		# Return per-module loaded counts
		return counts
	end

	#
	# Loads a module from the supplied file.
	#
	def load_module_from_file(path, file, loaded, recalc, counts, demand = false)

		if not ( demand or has_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', LEV_2)
			return false
		end

		# Substitute the base path
		path_base = file.sub(path + File::SEPARATOR, '')

		# Derive the name from the path with the exclusion of the .rb
		name = path_base.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		path_base.sub!(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		if (m = path_base.match(/^(.+?)#{File::SEPARATOR}+?/))
			type = m[1]
		else
			type = path_base
		end

		type.sub!(/s$/, '')


		added = nil

		begin
			wrap = ::Module.new
			wrap.module_eval(load_module_source(file), file)
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to error and failed version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
			errmsg = "#{e.class} #{e}"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Missing Metasploit class constant"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		# If the module indicates that it is not usable on this system, then we
		# will not try to use it.
		usable = false

		begin
			usable = respond_to?(:is_usable) ? added.is_usable : true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end

		if (usable == false)
			ilog("Skipping module in #{file} because is_usable returned false.", 'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{file}.", 'core', LEV_2)
		self.module_failed.delete(file)

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

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
	end


	#
	# Loads a module from the supplied archive path
	#
	def load_module_from_archive(path, file, loaded, recalc, counts, demand = false)
		
		if not ( demand or has_archive_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', LEV_2)
			return false
		end

		# Derive the name from the path with the exclusion of the .rb
		name = file.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		base = file.sub(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		if (m = base.match(/^(.+?)#{File::SEPARATOR}+?/))
			type = m[1]
		else
			type = base
		end

		type.sub!(/s$/, '')

		added = nil

		begin
			wrap = ::Module.new
			wrap.module_eval( ::FastLib.load(path, file), file )
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{path}::#{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{path}::#{file}due to error and failed version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
			errmsg = "#{e.class} #{e}"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Missing Metasploit class constant"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		# If the module indicates that it is not usable on this system, then we
		# will not try to use it.
		usable = false

		begin
			usable = respond_to?(:is_usable) ? added.is_usable : true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end

		if (usable == false)
			ilog("Skipping module in #{path}::#{file} because is_usable returned false.", 'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{path}::#{file}.", 'core', LEV_2)
		self.module_failed.delete(file)

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

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
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
	attr_accessor :module_failed # :nodoc:
	attr_accessor :enabled_types # :nodoc:

end

end

