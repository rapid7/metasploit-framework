# -*- coding: binary -*-
#
# Gems
#
require 'active_support/concern'

#
# Project
#
require 'msf/core/modules/loader/directory'
require 'msf/core/modules/loader/executable'

# Deals with loading modules for the {Msf::ModuleManager}
module Msf::ModuleManager::Loading
  extend ActiveSupport::Concern

  #
  # CONSTANTS
  #

  # Classes that can be used to load modules.
  LOADER_CLASSES = [
      Msf::Modules::Loader::Directory,
      Msf::Modules::Loader::Executable # TODO: XXX: When this is the first loader we can load normal exploits, but not payloads
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

  attr_accessor :module_load_error_by_path, :module_load_warnings

  # Called when a module is initially loaded such that it can be categorized
  # accordingly.
  #
  # @param class_or_module [Class<Msf::Module>, ::Module] either a module Class
  #   or a payload Module.
  # @param type [String] The module type.
  # @param reference_name The module reference name.
  # @param info [Hash{String => Array}] additional information about the module
  # @option info [Array<String>] 'files' List of paths to the ruby source files
  #   where +class_or_module+ is defined.
  # @option info [Array<String>] 'paths' List of module reference names.
  # @option info [String] 'type' The module type, should match positional
  #   +type+ argument.
  # @return [void]
  def on_module_load(class_or_module, type, reference_name, info={})
    module_set = module_set_by_type[type]
    module_set.add_module(class_or_module, reference_name, info)

    path = info['files'].first
    cache_in_memory(
        class_or_module,
        :path => path,
        :reference_name => reference_name,
        :type => type
    )

    # Automatically subscribe a wrapper around this module to the necessary
    # event providers based on whatever events it wishes to receive.
    auto_subscribe_module(class_or_module)

    # Notify the framework that a module was loaded
    framework.events.on_module_load(reference_name, class_or_module)
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
  # @param [String] path Path to a directory
  # @param [Hash] options
  # @option options [Boolean] :force Whether the force loading the modules even if they are unchanged and already
  #   loaded.
  # @option options [Array] :modules An array of regex patterns to search for specific modules
  # @return [Hash{String => Integer}] Maps module type to number of modules loaded
  def load_modules(path, options={})
    options.assert_valid_keys(:force, :whitelist)

    count_by_type = {}

    loaders.each do |loader|
      if loader.loadable?(path)
        count_by_type.merge!(loader.load_modules(path, options)) do |key, prev, now|
          prev + now
        end
      end
    end

    count_by_type
  end
end
