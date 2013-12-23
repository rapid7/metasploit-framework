# -*- coding: binary -*-
#
# Core
#
require 'pathname'

#
# Project
#
require 'metasploit/framework'
require 'msf/core'
require 'msf/core/module_set'

# Upper management decided to throw in some middle management
# because the modules were getting out of hand.  This bad boy takes
# care of the work of managing the interaction with modules in terms
# of loading and instantiation.
#
# @todo add unload support
class Msf::ModuleManager < Metasploit::Model::Base
  include Enumerable

  require 'msf/core/payload_set'

  require 'msf/core/module_manager/cache'
  include Msf::ModuleManager::Cache

  require 'msf/core/module_manager/module_paths'
  include Msf::ModuleManager::ModulePaths

  require 'msf/core/module_manager/module_sets'
  include Msf::ModuleManager::ModuleSets

  require 'msf/core/module_manager/reloading'
  include Msf::ModuleManager::Reloading

  #
  # Attributes
  #

  # @!attribute [rw] framework
  #   Framework for which this module manager is managing modules.
  #
  #   @return [Msf::Simple::Framework]
  attr_accessor :framework

  # @!attribute [rw] module_types
  #   The `Metasploit::Model::Module::Class#module_types` supported by this module manager.
  #
  #   @return [Array<String>] subset of `Metasploit::Model::Module::Type::ALL`.
  attr_writer :module_types

  #
  # Methods
  #

  def [](key)
    names = key.split("/")
    type = names.shift

    module_set = module_set_by_module_type[type]

    module_reference_name = names.join("/")
    module_set[module_reference_name]
  end

  # Creates a metasploit instance using the supplied `Mdm::Module::Class#full_name`.
  #
  # @param full_name [String] An `Mdm::Module::Class#full_name`.
  # @return [Msf::Module] Instance of the named module.
  # @return [nil] if there is no `Mdm::Module::Class` with the given name OR the metasploit class referenced by
  #   `Mdm::Module::Class` cannot be loaded (i.e. because its ancestor files don't exist on disk or have an error)
  def create(full_name)
    metasploit_instance = nil
    module_class = Mdm::Module::Class.where(full_name: full_name).first

    if module_class
      metasploit_class = cache.metasploit_class(module_class)

      if metasploit_class
        metasploit_instance = metasploit_class.new(framework: framework)
        framework.events.on_module_created(metasploit_instance)
      end
    end

    metasploit_instance
  end


  # Iterate over all modules in all sets
  #
  # @yieldparam full_name [String] The module's reference full_name
  # @yieldparam mod_class [Msf::Module] A module class
  def each
    module_set_by_module_type.each do |type, set|
      set.each do |name, mod_class|
        yield name, mod_class
      end
    end
  end

  def module_types
    unless instance_variable_defined? :@module_types
      if framework
        @module_types = framework.module_types
      end

      # handles framework being nil and framework.module_types being nil
      unless @module_types
        @module_types = Metasploit::Model::Module::Type::ALL
      end
    end

    @module_types
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
