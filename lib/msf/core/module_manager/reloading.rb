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

  # Reloads a payload module. This must be done by reloading the entire parent
  # directory to ensure the framework's complex payload "stitching" process
  # (combining stages, stagers, and mixins) is correctly executed. This is slower
  # but guarantees a fully-functional reloaded module.
  def reload_payload_module(metasploit_class, original_instance = nil)
    # Step 1: Get all necessary identifiers from the original module class.
    fullname = metasploit_class.fullname
    refname = metasploit_class.refname
    type = metasploit_class.type
    file_path = metasploit_class.file_path

    # Store the original datastore so we can restore its state.
    original_datastore = original_instance&.datastore&.copy

    # Step 2: Manually purge the old module from the framework's caches.
    module_set.delete(module_reference_name) if module_set
    if (aliases_for_fullname = inv_aliases[fullname])
      aliases_for_fullname.each { |a| aliases.delete(a) }
      inv_aliases.delete(fullname)
    end

    # Step 3: Get the module's parent directory path.
    module_info = module_info_by_path[file_path]
    unless module_info && (parent_path = module_info[:parent_path])
      raise Msf::LoadError, "Could not find cached module information for path: #{file_path}"
    end

    # Step 4: Use the core framework loader to reload the entire parent directory.
    # This is the only way to reliably trigger the payload stitching logic.
    load_modules(parent_path, force: true)

    # Step 5: Now that the framework has completed its full reload process,
    # use the public API to get a new instance of our reloaded module.
    new_instance = framework.modules.create(fullname)

    if new_instance.blank?
      raise "Failed to create a new instance of #{fullname} after reloading. The module file may be broken."
    end

    # Step 6: Restore the datastore to the new, fully-functional instance.
    if original_datastore
      new_instance.datastore.merge!(original_datastore)
    end

    # Return the new instance, which the framework will make the active module.
    return new_instance
  rescue StandardError => e
    elog("Failed to reload payload #{fullname}: #{e.message}")
    raise "Failed to reload payload: #{e.message}"
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
