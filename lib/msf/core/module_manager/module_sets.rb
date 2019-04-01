# -*- coding: binary -*-
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
    module_set(Msf::MODULE_AUX)
  end

  #
  # Returns the set of loaded encoder module classes.
  #
  def encoders
    module_set(Msf::MODULE_ENCODER)
  end

  #
  # Returns the set of loaded exploit module classes.
  #
  def exploits
    module_set(Msf::MODULE_EXPLOIT)
  end

  def init_module_set(type)
    self.enablement_by_type[type] = true
    case type
      when Msf::MODULE_PAYLOAD
        instance = Msf::PayloadSet.new
      else
        instance = Msf::ModuleSet.new(type)
    end

    self.module_set_by_type[type] = instance

    # Set the module set's framework reference
    instance.framework = self.framework
  end

  #
  # Provide a list of module names of a specific type
  #
  def module_names(set)
    module_set_by_type[set] ? module_set_by_type[set].keys.dup : []
  end

  #
  # Returns all of the modules of the specified type
  #
  def module_set(type)
    module_set_by_type[type]
  end

  #
  # Provide a list of the types of modules in the set
  #
  def module_types
    module_set_by_type.keys.dup
  end

  #
  # Returns the set of loaded nop module classes.
  #
  def nops
    module_set(Msf::MODULE_NOP)
  end

  #
  # Returns the set of loaded payload module classes.
  #
  def payloads
    module_set(Msf::MODULE_PAYLOAD)
  end

  #
  # Returns the set of loaded auxiliary module classes.
  #
  def post
    module_set(Msf::MODULE_POST)
  end

  def evasion
    module_set(Msf::MODULE_EVASION)
  end

  def type_enabled?(type)
    enablement_by_type[type] || false
  end

  protected

  attr_accessor :enablement_by_type # :nodoc:
  attr_accessor :module_set_by_type # :nodoc:
end
