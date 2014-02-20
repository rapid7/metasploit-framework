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
  # @param [String] path
  # @param [Hash] opts
  # @option opts [Array] whitelist An array of regex patterns to search for specific modules
  # @return (see Msf::Modules::Loader::Base#load_modules)
  def add_module_path(path, opts={})
    nested_paths = []

    # remove trailing file separator
    path_without_trailing_file_separator = path.sub(/#{File::SEPARATOR}$/, '')

    # Make the path completely canonical
    pathname = Pathname.new(path_without_trailing_file_separator).expand_path
    extension = pathname.extname

    if extension == Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION
      unless pathname.exist?
        raise ArgumentError, "The path supplied does not exist", caller
      end

      nested_paths << pathname.to_s
    else
      # Make sure the path is a valid directory
      unless pathname.directory?
        raise ArgumentError, "The path supplied is not a valid directory.", caller
      end

      nested_paths << pathname.to_s

      # Identify any fastlib archives inside of this path
      fastlib_glob = pathname.join('**', "*#{Msf::Modules::Loader::Archive::ARCHIVE_EXTENSION}")

      Dir.glob(fastlib_glob).each do |fastlib_path|
        nested_paths << fastlib_path
      end
    end

    # Update the module paths appropriately
    self.module_paths = (module_paths + nested_paths).flatten.uniq

    # Load all of the modules from the nested paths
    count_by_type = {}
    nested_paths.each { |path|
      path_count_by_type = load_modules(path, opts.merge({:force => false}))

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