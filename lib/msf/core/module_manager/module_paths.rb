#
# Gems
#
require 'active_support/concern'
require 'active_support/core_ext/hash'
require 'active_support/core_ext/module'

# Deals with module paths in the {Msf::ModuleManager}
module Msf::ModuleManager::ModulePaths
  extend ActiveSupport::Concern

  # Adds a path to {#cache} and then searches the path for modules.
  #
  # @param path [String] a `Metasploit::Model::Module::Path#real_path`.
	# @param options (see Metasploit::Framework::PathSet::Base#add)
	# @option (see Metasploit::Framework::PathSet::Base#add)
  # @return (see Msf::Modules::Loader::Base#load_modules)
  def add_path(path, options={})
		module_path = cache.path_set.add(path, options)

    # Load all of the modules from the nested paths
		count_by_type = cache.prefetch(only: module_path)

    count_by_type
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