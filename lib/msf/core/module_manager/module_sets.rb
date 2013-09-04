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

  #
  # Returns the set of loaded auxiliary module classes.
  #
  def auxiliary
    module_set(Metasploit::Model::Module::Type::AUX)
  end

  #
  # Returns the set of loaded encoder module classes.
  #
  def encoders
    module_set(Metasploit::Model::Module::Type::ENCODER)
  end

  #
  # Returns the set of loaded exploit module classes.
  #
  def exploits
    module_set(Metasploit::Model::Module::Type::EXPLOIT)
  end

  def init_module_set(type)
    self.enablement_by_module_type[type] = true
    case type
      when Metasploit::Model::Module::Type::PAYLOAD
        instance = Msf::PayloadSet.new
      else
        instance = Msf::ModuleSet.new(type)
    end

    self.module_set_by_module_type[type] = instance

    # Set the module set's framework reference
    instance.framework = self.framework
  end

  #
  # Provide a list of module names of a specific type
  #
  def module_names(set)
    module_set_by_module_type[set] ? module_set_by_module_type[set].keys.dup : []
  end

  #
  # Returns all of the modules of the specified type
  #
  def module_set(type)
    module_set_by_module_type[type]
  end

  # Provide a list of the types of modules being managed by the module manager.
  #
	# @return [Array<String>]
  def module_types
    module_set_by_module_type.keys.dup
  end

  #
  # Returns the set of loaded nop module classes.
  #
  def nops
    module_set(Metasploit::Model::Module::Type::NOP)
  end

  #
  # Returns the set of loaded payload module classes.
  #
  def payloads
    module_set(Metasploit::Model::Module::Type::PAYLOAD)
  end

  #
  # Returns the set of loaded auxiliary module classes.
  #
  def post
    module_set(Metasploit::Model::Module::Type::POST)
  end

	# Whether the given `module_type` is enabled and being managed by this module
	# manager.
	#
	# @param module_type [String] a module type
	# @return [Boolean]
	# @see Metasploit::Model::Module::Type
  def module_type_enabled?(module_type)
    enablement_by_module_type[module_type] || false
  end

  protected

  attr_accessor :enablement_by_module_type # :nodoc:
  attr_accessor :module_set_by_module_type # :nodoc:
end
