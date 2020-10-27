# -*- coding: binary -*-
# Concerns reloading modules
module Msf::ModuleManager::Reloading
  # Reloads the module specified in mod.  This can either be an instance of a module or a module class.
  #
  # @param [Msf::Module, Class] mod either an instance of a module or a module class
  # @return (see Msf::Modules::Loader::Base#reload_module)
  def reload_module(mod)
    # if it's can instance, then get its class
    if mod.is_a? Msf::Module
      metasploit_class = mod.class
    else
      metasploit_class = mod
    end

    if aliased_as = self.inv_aliases[metasploit_class.fullname]
      aliased_as.each do |a|
        self.aliases.delete a
      end
      self.inv_aliases.delete metasploit_class.fullname
    end

    namespace_module = metasploit_class.parent
    loader = namespace_module.loader
    loader.reload_module(mod)
  end

  # Reloads modules from all module paths
  #
  # @return (see Msf::ModuleManager::Loading#load_modules)
  def reload_modules
    self.enablement_by_type.each_key do |type|
      module_set_by_type[type].clear
      init_module_set(type)
    end
    self.aliases.clear
    self.inv_aliases.clear

    # default the count to zero the first time a type is accessed
    count_by_type = Hash.new(0)

    module_paths.each do |path|
      path_count_by_type = load_modules(path, :force => true)

      # merge count with count from other paths
      path_count_by_type.each do |type, count|
        count_by_type[type] += count
      end
    end

    refresh_cache_from_module_files

    count_by_type
  end
end
