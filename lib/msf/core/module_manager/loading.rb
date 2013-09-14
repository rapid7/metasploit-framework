#
# Gems
#
require 'active_support/concern'

# Deals with loading modules for the {Msf::ModuleManager}
module Msf::ModuleManager::Loading
  extend ActiveSupport::Concern

  attr_accessor :module_load_error_by_path

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
    module_set = module_set_by_module_type[type]
    module_set.add_module(class_or_module, reference_name, info)

    # Automatically subscribe a wrapper around this module to the necessary
    # event providers based on whatever events it wishes to receive.
    auto_subscribe_module(class_or_module)

    # Notify the framework that a module was loaded
    framework.events.on_module_load(reference_name, class_or_module)
  end

  protected

  # Load all of the modules from the supplied directory
  #
  # @param [String] path Path to a directory
  # @param [Hash] options
  # @option options [Boolean] :force Whether the force loading the modules even if they are unchanged and already
  #   loaded.
  # @option options [Array] :modules An array of regex patterns to search for specific modules
  # @return [Hash{String => Integer}] Maps module type to number of modules loaded
  def load_modules(path, options={})
    options.assert_valid_keys(:force, :whitelist)

    count_by_type = cache.path_loader.load_modules(path, options)

    count_by_type
  end
end
