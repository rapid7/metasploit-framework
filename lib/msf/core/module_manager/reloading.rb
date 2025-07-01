# -*- coding: binary -*-

# Concerns reloading modules
module Msf::ModuleManager::Reloading
  # Reloads the module specified in mod.  This can either be an instance of a module or a module class.
  #
  # @param [Msf::Module, Class] mod either an instance of a module or a module class
  # @return (see Msf::Modules::Loader::Base#reload_module)
  def reload_module(mod)
    # if it's an instance, then get its class
    if mod.is_a? Msf::Module
      metasploit_class = mod.class
      original_instance = mod
    else
      metasploit_class = mod
      original_instance = nil
    end

    # Handle aliases cleanup
    if (aliased_as = inv_aliases[metasploit_class.fullname])
      aliased_as.each do |a|
        aliases.delete a
      end
      inv_aliases.delete metasploit_class.fullname
    end

    # Special handling for payload modules
    if mod&.payload?
      return reload_payload_module(metasploit_class, original_instance)
    end

    # Standard module reloading for non-payloads
    namespace_module = metasploit_class.module_parent

    # Check if the namespace module has a loader
    unless namespace_module.respond_to?(:loader)
      raise "Module #{metasploit_class.fullname} namespace does not have a loader"
    end

    loader = namespace_module.loader
    loader.reload_module(mod)
  end

  private

  # Reload payload modules by clearing and reloading the entire payload set
  # This is necessary because payloads have complex interdependencies
  def reload_payload_module(metasploit_class, original_instance = nil)
    module_type = 'payload'
    module_reference_name = metasploit_class.fullname.sub(%r{^payload/}, '')

    # Store original datastore if we have an instance
      original_datastore = original_instance&.datastore.copy

    # Clear the specific payload from the module set
    module_set = module_set_by_type[module_type]
    if module_set
      module_set.delete(module_reference_name)
    end

    # For payloads, we need to reload the entire payload ecosystem
    # because of stage/stager dependencies
    reload_payload_set

    # Try to get the reloaded module class
    reloaded_module_class = module_set_by_type[module_type][module_reference_name]

    if reloaded_module_class.nil?
      raise "Failed to reload payload module: #{metasploit_class.fullname} not found after reload"
    end

    # Create a new instance of the reloaded module
    new_instance = reloaded_module_class.new

    # Restore the original datastore if we had one
    if original_datastore
      new_instance.datastore.merge!(original_datastore)
    end

    return new_instance
  rescue StandardError => e
    elog("Failed to reload payload #{metasploit_class.fullname}: #{e.message}")
    raise "Failed to reload payload: #{e.message}"
  end

  # Reload the entire payload module set
  def reload_payload_set
    module_type = 'payload'

    # Clear existing payload modules
    if module_set_by_type[module_type]
      module_set_by_type[module_type].clear
    end

    # Reinitialize the payload module set
    init_module_set(module_type)

    # Reload payloads from all module paths
    module_paths.each do |path|
      # Load payloads with force flag to ensure reload
      load_modules(path, type: [module_type], force: true)
    rescue StandardError => e
      wlog("Warning: Could not reload payloads from #{path}: #{e.message}")
    end
  end

  public

  # Reloads modules from all module paths
  #
  # @return (see Msf::ModuleManager::Loading#load_modules)
  def reload_modules
    enablement_by_type.each_key do |type|
      module_set_by_type[type].clear
      init_module_set(type)
    end

    aliases.clear
    inv_aliases.clear

    # default the count to zero the first time a type is accessed
    count_by_type = Hash.new(0)

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
