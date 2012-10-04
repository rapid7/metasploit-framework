#
# Gems
#
require 'active_support/concern'

# Deals with module paths in the {Msf::ModuleManager}
module Msf::ModuleManager::ModulePaths
  extend ActiveSupport::Concern

  # Adds a path to be searched for new modules.
  #
  # @param [String] path
  # @return (see Msf::Modules::Loader::Base#load_modules)
  def add_module_path(path)
    nested_paths = []

    # remove trailing file separator
    path.sub!(/#{File::SEPARATOR}$/, '')

    pathname = Pathname.new(path)
    extension = pathname.extname

    if extension == Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION
      unless pathname.exist?
        raise RuntimeError, "The path supplied does not exist", caller
      end

      nested_paths << pathname.expand_path.to_path
    else
      # Make the path completely canonical
      pathname = Pathname.new(path).expand_path

      # Make sure the path is a valid directory
      unless pathname.directory?
        raise RuntimeError, "The path supplied is not a valid directory.", caller
      end

      nested_paths << pathname.to_path

      # Identify any fastlib archives inside of this path
      fastlib_glob = pathname.join('**', "*#{Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION}")

      Dir.glob(fastlib_glob).each do |fastlib_path|
        nested_pathnames << fastlib_path
      end
    end

    # Update the module paths appropriately
    self.module_paths = (module_paths + nested_paths).flatten.uniq

    # Load all of the modules from the nested paths
    count_by_type = {}
    nested_paths.each { |path|
      path_count_by_type = load_modules(path, :force => false)

      # merge hashes
      path_count_by_type.each do |type, path_count|
        accumulated_count = count_by_type.fetch(type, 0)
        count_by_type[type] = accumulated_count + path_count
      end
    }

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
end