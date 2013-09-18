#
# Gems
#
require 'active_support/concern'

#
# Project
#

# Defines the MODULE_* constants
require 'msf/core/constants'

# Concerns the various type-specific module sets in a {Msf::ModuleManager}
module Msf::ModuleManager::ModuleSets
  extend ActiveSupport::Concern

  module ClassMethods
    def module_set_class_by_module_type
      unless instance_variable_defined? :@module_set_class_by_module_type
        @module_set_class_by_module_type ||= Hash.new { |hash, module_type|
          hash[module_type] = Msf::ModuleSet
        }

        @module_set_class_by_module_type[Metasploit::Model::Module::Type::PAYLOAD] = Msf::PayloadSet
      end

      @module_set_class_by_module_type
    end
  end

  #
  # Instance Methods
  #

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each do |module_type, directory|
    define_method(directory) do
      module_set_by_module_type[module_type]
    end
  end

  def module_set_by_module_type
    @module_set_by_module_type ||= module_types.each_with_object({}) do |module_type, module_set_by_module_type|
      module_set_class = self.class.module_set_class_by_module_type[module_type]
      module_set = module_set_class.new(
          module_manager: self,
          module_type: module_type
      )
      module_set.valid!

      module_set_by_module_type[module_type] = module_set
    end
  end

  #
  # Provide a list of module names of a specific type
  #
  def module_names(set)
    module_set_by_module_type[set] ? module_set_by_module_type[set].keys.dup : []
  end

  # Whether the given `module_type` is enabled and being managed by this module
  # manager.
  #
  # @param module_type [String] a module type
  # @return [Boolean]
  # @see Metasploit::Model::Module::Type
  def module_type_enabled?(module_type)
    module_set_by_module_type[module_type].nil?
  end
end
