#
# Gems
#
require 'active_support/concern'

#
# Project
#
require 'msf/core/modules/loader/archive'
require 'msf/core/modules/loader/directory'

# Deals with loading modules for the {Msf::ModuleManager}
module Msf::ModuleManager::Loading
  extend ActiveSupport::Concern

  #
  # CONSTANTS
  #

  # Classes that can be used to load modules.
  LOADER_CLASSES = [
      Msf::Modules::Loader::Archive,
      Msf::Modules::Loader::Directory
  ]

  def file_changed?(path)
    changed = false

    module_info = self.module_info_by_path[path]

    # if uncached then it counts as changed
    # Payloads can't be cached due to stage/stager matching
    if module_info.nil? or module_info[:type] == Msf::MODULE_PAYLOAD
      changed = true
    else
      begin
        current_modification_time = ::File.mtime(path).to_i
      rescue ::Errno::ENOENT
        # if the file does not exist now, that's a change
        changed = true
      else
        cached_modification_time = module_info[:modification_time].to_i

        # if the file's modification time's different from the cache, then it's changed
        if current_modification_time != cached_modification_time
          changed = true
        end
      end
    end

    changed
  end

  attr_accessor :module_load_error_by_path

  # Called when a module is initially loaded such that it can be
  # categorized accordingly.
  #
  def on_module_load(mod, type, name, modinfo)
    dup = module_set_by_type[type].add_module(mod, name, modinfo)

    # Automatically subscribe a wrapper around this module to the necessary
    # event providers based on whatever events it wishes to receive.
    auto_subscribe_module(dup)

    # Notify the framework that a module was loaded
    framework.events.on_module_load(name, dup)

    dup
  end

  protected

  # Return list of {LOADER_CLASSES} instances that load modules into this module manager
  def loaders
    unless instance_variable_defined? :@loaders
      @loaders = LOADER_CLASSES.collect { |klass|
        klass.new(self)
      }
    end

    @loaders
  end

  # Load all of the modules from the supplied directory or archive
  #
  # @param [String] path Path to a directory or Fastlib archive
  # @param [Hash] options
  # @option options [Boolean] :force Whether the force loading the modules even if they are unchanged and already
  #   loaded.
  # @return [Hash{String => Integer}] Maps module type to number of modules loaded
  def load_modules(path, options={})
    options.assert_valid_keys(:force)

    count_by_type = {}

    loaders.each do |loader|
      if loader.loadable?(path)
        count_by_type = loader.load_modules(path, options)

        break
      end
    end

    count_by_type
  end
end
