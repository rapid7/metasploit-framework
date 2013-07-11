#
# Gems
#
require 'active_support/concern'
require 'active_support/core_ext/hash'
require 'active_support/core_ext/module'

# Deals with module paths in the {Msf::ModuleManager}
module Msf::ModuleManager::ModulePaths
	extend ActiveSupport::Concern

	# Adds a path to be searched for new modules.
	#
	# @param real_path [String] a path.
	# @param options [Hash{Symbol => String}]
	# @option options [String] :gem The name of the gem that is adding this module
	#   path to metasploit-framework.  For paths normally added by
	#   metasploit-framework itself, this would be `'metasploit-framework'`, while
	#   for Metasploit Pro this would be `'metasploit-pro'`.  The name used for
	#   `gem` does not have to be a gem on rubygems, it just functions as a
	#   namespace for {#name} so that projects using metasploit-framework do not
	#   need to worry about collisions on {#name} which could disrupt the cache
	#   behavior.
	# @option options [String] :name The name of the module path scoped to :gem.
	#   :gem and :name uniquely identify this path so that if
	#   `real_path` changes, the entire cache does not need to be invalidated
	#   because the change in `real_path` will still be tied to the same (:gem,
	#   :name) tuple.
	# @return (see Msf::Modules::Loader::Base#load_modules)
	# @see Mdm::Module::Path#gem
	def add_module_path(path, options={})
		options.assert_valid_keys(:gem, :name)
		added_module_paths = []

		# remove trailing file separator
		path_without_trailing_file_separator = path.sub(/#{File::SEPARATOR}$/, '')

		# Make the path completely canonical
		pathname = Pathname.new(path_without_trailing_file_separator).expand_path
		extension = pathname.extname

		if extension == Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION
			unless pathname.exist?
				raise ArgumentError, "The path supplied does not exist", caller
			end

			module_path = module_path_set.add(path, options)
			added_module_paths << module_path
		else
			# Make sure the path is a valid directory
			unless pathname.directory?
				raise ArgumentError, "The path supplied is not a valid directory.", caller
			end

			module_path = module_path_set.add(path, options)
			added_module_paths << module_path

			# Identify any fastlib archives inside of this path
			fastlib_glob = pathname.join('**', "*#{Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION}")

			Dir.glob(fastlib_glob).each do |fastlib_path|
				# nested fastlibs don't get :gem since there can be more than one of
				# them.
				module_path = module_path_set.add(fastlib_path)
				added_module_paths << module_path
			end
		end

		# Load all of the modules from the nested paths
		count_by_type = {}
		added_module_paths.each { |module_path|
			module_path_count_by_type = load_modules(
					module_path.real_path,
					:force => false
			)

			# merge hashes
			module_path_count_by_type.each do |type, module_path_count|
				accumulated_count = count_by_type.fetch(type, 0)
				count_by_type[type] = accumulated_count + module_path_count
			end
		}

		return count_by_type
	end

	# (see Metasploit::Framework::Module::PathSet#remove)
	def remove_module_path(options={})
		module_path_set.remove(options)
	end

	protected

	# @return [Metasploit::Framework::Module::PathSet]
	def module_path_set
		@module_path_set ||= module_path_set_class.new(:framework => framework)
	end

	# Returns Class for {#module_path_set}.
	#
	# @return [Class] {Metasploit::Framework::Module::PathSet::DataBase} if the
	#   database is active.  {Metasploit::Framework::Module::PathSet::Memory} if
	#   the database is not active.
	def module_path_set_class
		if framework.db.active?
			Metasploit::Framework::Module::PathSet::Database
		else
			Metasploit::Framework::Module::PathSet::Memory
		end
	end
end
