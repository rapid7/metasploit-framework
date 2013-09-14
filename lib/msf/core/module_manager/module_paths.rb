#
# Gems
#
require 'active_support/concern'

# Deals with module paths in the {Msf::ModuleManager}
module Msf::ModuleManager::ModulePaths
  extend ActiveSupport::Concern

  # Adds a path to {#cache} and then searches the path for modules.
  #
  # @param path [String] a `Metasploit::Model::Module::Path#real_path`.
  # @param options (see Metasploit::Framework::PathSet::Base#add)
  # @option (see Metasploit::Framework::PathSet::Base#add)
  # @return [Metasploit::Model::Path::Load] load of `Metasploit::Model::Module::Path` added to
  #   {Msf::ModuleManager::Cache#cache}.
  def add_path(path, options={})
    module_path = cache.path_set.add(path, options)

    # Load all of the modules from the nested paths
    module_path_loads = cache.prefetch(only: module_path)
    module_path_load = module_path_loads.first

    module_path_load
  end
end