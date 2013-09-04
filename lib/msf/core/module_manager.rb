# -*- coding: binary -*-
#
# Core
#
require 'pathname'

#
# Project
#
require 'fastlib'
require 'metasploit/framework'
require 'msf/core'
require 'msf/core/module_set'

module Msf
  # Upper management decided to throw in some middle management
  # because the modules were getting out of hand.  This bad boy takes
  # care of the work of managing the interaction with modules in terms
  # of loading and instantiation.
  #
  # @todo add unload support
  class ModuleManager
    include Msf::Framework::Offspring

    require 'msf/core/payload_set'

    # require here so that Msf::ModuleManager is already defined
    require 'msf/core/module_manager/cache'
    require 'msf/core/module_manager/loading'
    require 'msf/core/module_manager/module_paths'
    require 'msf/core/module_manager/module_sets'
    require 'msf/core/module_manager/reloading'

    include Msf::ModuleManager::Cache
    include Msf::ModuleManager::Loading
    include Msf::ModuleManager::ModulePaths
    include Msf::ModuleManager::ModuleSets
    include Msf::ModuleManager::Reloading

    include Enumerable

    #
    # CONSTANTS
    #

    # Maps module type directory to its module type.
    TYPE_BY_DIRECTORY = Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.invert

    def [](key)
      names = key.split("/")
      type = names.shift

      module_set = module_set_by_module_type[type]

      module_reference_name = names.join("/")
      module_set[module_reference_name]
    end

    # Creates a module instance using the supplied reference name.
    #
    # @param name [String] A module reference name.  It may optionally
    #   be prefixed with a "<type>/", in which case the module will be
    #   created from the {Msf::ModuleSet} for the given <type>.
    #   Otherwise, we step through all sets until we find one that
    #   matches.
    # @return (see Msf::ModuleSet#create)
    def create(name)
      # Check to see if it has a module type prefix.  If it does,
      # try to load it from the specific module set for that type.
      names = name.split("/")
      potential_type_or_directory = names.first

      # if first name is a type
      if Metasploit::Model::Module::Type::ALL.include? potential_type_or_directory
        type = potential_type_or_directory
      # if first name is a type directory
			else
				directory = potential_type_or_directory
        type = Metasploit::Framework::Module::Ancestor::MODULE_TYPE_BY_DIRECTORY[directory]
      end

      module_instance = nil
      if type
        module_set = module_set_by_module_type[type]

        # First element in names is the type, so skip it
        module_reference_name = names[1 .. -1].join("/")
        module_instance = module_set.create(module_reference_name)
      else
        # Then we don't have a type, so we have to step through each set
        # to see if we can create this module.
        module_set_by_module_type.each do |_, set|
          module_reference_name = names.join("/")
          module_instance = set.create(module_reference_name)
          break if module_instance
        end
      end

      module_instance
    end


    # Iterate over all modules in all sets
    #
    # @yieldparam name [String] The module's reference name
    # @yieldparam mod_class [Msf::Module] A module class
    def each
      module_set_by_module_type.each do |type, set|
        set.each do |name, mod_class|
          yield name, mod_class
        end
      end
    end


    # @param [Msf::Framework] framework The framework for which this instance is
		#   managing the modules.
    # @param [Array<String>] types List of module types to load.  Defaults to
		#   all module types in `Metasploit::Model::Module::Type::ALL`.
    def initialize(framework, types=Metasploit::Model::Module::Type::ALL)
      #
      # defaults
      #

      self.module_info_by_path = {}
      self.enablement_by_module_type = {}
      self.module_load_error_by_path = {}
      self.module_set_by_module_type = {}

      #
      # from arguments
      #

      self.framework = framework

      types.each { |type|
        init_module_set(type)
      }
    end

    protected

    # This method automatically subscribes a module to whatever event
    # providers it wishes to monitor.  This can be used to allow modules
    # to automatically execute or perform other tasks when certain
    # events occur.  For instance, when a new host is detected, other
    # aux modules may wish to run such that they can collect more
    # information about the host that was detected.
    #
    # @param klass [Class<Msf::Module>] The module class
    # @return [void]
    def auto_subscribe_module(klass)
      # If auto-subscribe has been disabled
      if (framework.datastore['DisableAutoSubscribe'] and
          framework.datastore['DisableAutoSubscribe'] =~ /^(y|1|t)/)
        return
      end

      # If auto-subscription is enabled (which it is by default), figure out
      # if it subscribes to any particular interfaces.
      inst = nil

      #
      # Exploit event subscriber check
      #
      if (klass.include?(Msf::ExploitEvent) == true)
        framework.events.add_exploit_subscriber((inst) ? inst : (inst = klass.new))
      end

      #
      # Session event subscriber check
      #
      if (klass.include?(Msf::SessionEvent) == true)
        framework.events.add_session_subscriber((inst) ? inst : (inst = klass.new))
      end
    end

  end
end
