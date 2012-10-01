# Concerns reloading modules
module Msf::ModuleManager::Reloading
  extend ActiveSupport::Concern

  # Reloads the module specified in mod.  This can either be an instance of a module or a module class.
  #
  # @param [Msf::Module, Class] mod either an instance of a module or a module class
  def reload_module(mod)
    refname = mod.refname

    dlog("Reloading module #{refname}...", 'core')

    # if it's can instance, then get its class
    if mod.is_a? Msf::Module
      metasploit_class = mod.class
    else
      metasploit_class = mod
    end

    namespace_module = metasploit_class.parent
    loader = namespace_module.loader
    loader.reload_module(mod)
  end

  #
  # Reloads modules from all module paths
  #
  def reload_modules
    self.module_history = {}
    self.clear

    self.enablement_by_type.each_key do |type|
      module_set_by_type[type].clear
      init_module_set(type)
    end

    # The number of loaded modules in the following categories:
    # auxiliary/encoder/exploit/nop/payload/post
    count = 0
    module_paths.each do |path|
      mods = load_modules(path, true)
      mods.each_value {|c| count += c}
    end

    rebuild_cache

    count
  end
end