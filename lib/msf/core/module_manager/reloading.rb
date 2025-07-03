# -*- coding: binary -*-
# Concerns reloading modules
require 'pry'
require 'pry-byebug'
module Msf::ModuleManager::Reloading
  # Reloads the module specified in mod.  This can either be an instance of a module or a module class.
  #
  # @param [Msf::Module, Class] mod either an instance of a module or a module class
  # @return (see Msf::Modules::Loader::Base#reload_module)
  def reload_module(mod)
    # if it's an instance, then get its class
    binding.pry
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

    if mod.payload?
      return reload_payload_module(mod)
    end
    
    namespace_module = metasploit_class.module_parent
    
    # Check if the namespace module has a loader
    unless namespace_module.respond_to?(:loader)
      elog("Module does not have loader")
      return mod
    end

    loader = namespace_module.loader
    loader.reload_module(mod)
  end
  # Reload payload module, separately from other categories. This is due to complexity of payload module and due to the fact they don't follow class structure as rest of the modules. 
  # @param [Msf::Module, Class] mod either an instance of a module or a module class
  # @return (see Msf::Modules::Loader::Base#reload_module)
  def reload_payload_module(mod)
    if mod.is_a? Msf::Module
      metasploit_class = mod.class
      original_instance = mod
    else
      metasploit_class = mod
      original_instance = nil
    end 
    binding.pry 

    if (module_set = self.module_set_by_type.fetch(metasploit_class.type, nil))
      module_set.delete(metasploit_class.refname)
    end

    module_info = self.module_info_by_path[metasploit_class.file_path]
    unless module_info && (parent_path = module_info[:parent_path])
      elog("Failed to get parent_path from module object")
      return mod
    end

    case original_instance&.payload_type
      when Msf::Payload::Type::Single
        prepend_path = 'singles'
      when Msf::Payload::Type::Stager
        prepend_path = 'stagers'
      when Msf::Payload::Type::Stage
        prepend_path = 'stages'
      when Msf::Payload::Type::Adapter
        prepend_path = 'adapters'
    end

    full_reference_name = File.join(prepend_path, module_info[:reference_name])
    self.loaders.each { |loader| loader.load_module(parent_path,module_info[:type], full_reference_name, {:force => true}) }


    # Get reloaded module
    new_instance = framework.modules.create(metasploit_class.fullname)

    if new_instance.blank?
      elog("Failed create new instance")
      return mod
    end

    # Restore the datastore 
    new_instance.datastore.merge!(original_instance.datastore)


    # Return the new instance, which the framework will make the active module.
    return new_instance
  rescue StandardError => e
    elog("Failed to reload payload #{fullname}: #{e.message}")
    return mod
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

    framework.init_module_paths unless framework.module_paths_inited

    module_paths.each do |path|
      path_count_by_type = load_modules(path, force: true)

      # merge count with count from other paths
      path_count_by_type.each do |type, count|
        count_by_type[type] += count
      end
    end

    refresh_cache_from_module_files

    count_by_type
  end
end
