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
  # @param path [String] a module path, archive path, or a directory that
	#   contains archives.
	# @param options (see Metasploit::Framework::PathSet::Base#add)
	# @option (see Metasploit::Framework::PathSet::Base#add)
  # @return (see Msf::Modules::Loader::Base#load_modules)
  def add_path(path, options={})
		module_paths = []

    # remove trailing file separator
    path_without_trailing_file_separator = path.sub(/#{File::SEPARATOR}$/, '')

    # Make the path completely canonical
    pathname = Pathname.new(path_without_trailing_file_separator).expand_path
    extension = pathname.extname

    if extension == Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION
      unless pathname.exist?
        raise ArgumentError, "The path supplied does not exist", caller
      end

			module_paths << path_set.add(pathname.to_path, options)
    else
      # Make sure the path is a valid directory
      unless pathname.directory?
        raise ArgumentError, "The path supplied is not a valid directory.", caller
      end

			module_paths << path_set.add(pathname.to_path, options)

      # Identify any fastlib archives inside of this path
      fastlib_glob = pathname.join('**', "*#{Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION}")

      Dir.glob(fastlib_glob) do |fastlib_path|
			  # no support for symbolic (gem, name) for fastlibs since they can be
				# under multiple directories and encoding all those directories in the
				# :name option will defeat the purpose of symbolic names allowing moves.
				module_paths << path_set.add(fastlib_path)
      end
    end

    # Load all of the modules from the nested paths
    count_by_type = {}
    module_paths.each do |module_path|
			path_count_by_type = load_modules(
					module_path.real_path,
					force: false
			)

			# merge hashes
			path_count_by_type.each do |type, path_count|
				accumulated_count = count_by_type.fetch(type, 0)
				count_by_type[type] = accumulated_count + path_count
			end
		end

    return count_by_type
	end

  #
  # Removes a path from which to search for modules.
  #
  def remove_module_path(path)
    module_paths.delete(path)
    module_paths.delete(::File.expand_path(path))
	end

  protected

  attr_accessor :module_paths # :nodoc:

	def path_set
		@path_set = Metasploit::Framework::Module::PathSet::Database.new
	end
end