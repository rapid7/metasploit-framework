# -*- coding: binary -*-
#
# Core
#
require 'pathname'

#
# Project
#
require 'fastlib'
require 'msf/core'
require 'msf/core/module_set'

module Msf
  ###
  #
  # Upper management decided to throw in some middle management
  # because the modules were getting out of hand.  This bad boy
  # takes care of the work of managing the interaction with
  # modules in terms of loading and instantiation.
  #
  # TODO:
  #
  #   - add unload support
  #
  ###
  class ModuleManager < ModuleSet
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

    #
    # CONSTANTS
    #

    # Regex for parsing the module type from a module name.
    MODULE_TYPE_FROM_NAME_REGEX = /^(#{MODULE_TYPES.join('|')})\/(.*)$/

    # Overrides the module set method for adding a module so that some extra
    # steps can be taken to subscribe the module and notify the event
    # dispatcher.
    def add_module(mod, name, file_paths)
      # Call the module set implementation of add_module
      dup = super

      # Automatically subscribe a wrapper around this module to the necessary
      # event providers based on whatever events it wishes to receive.  We
      # only do this if we are the module manager instance, as individual
      # module sets need not subscribe.
      auto_subscribe_module(dup)

      # Notify the framework that a module was loaded
      framework.events.on_module_load(name, dup)
    end

    #
    # Creates a module using the supplied name.
    #
    def create(name)
      # Check to see if it has a module type prefix.  If it does,
      # try to load it from the specific module set for that type.
      match = name.match(MODULE_TYPE_FROM_NAME_REGEX)

      if match
        type = match[1]
        module_set = module_set_by_type[type]

        module_reference_name = match[2]
        module_set.create(module_reference_name)
      # Otherwise, just try to load it by name.
      else
        super
      end
    end

    def demand_load_module(mtype, mname)
      n = self.cache.keys.select { |k|
        self.cache[k][:mtype]   == mtype and
            self.cache[k][:refname] == mname
      }.first

      return nil unless n
      m = self.cache[n]

      if m[:file] =~ /^(.*)\/#{m[:mtype]}s?\//
        path = $1
        load_module_from_file(path, m[:file], nil, nil, nil, true)
      else
        dlog("Could not demand load module #{mtype}/#{mname} (unknown base name in #{m[:file]})", 'core', LEV_2)
        nil
      end
    end

    #
    # Initializes an instance of the overall module manager using the supplied
    # framework instance. The types parameter can be used to only load specific
    # module types on initialization
    #
    def initialize(framework, types=MODULE_TYPES)
      #
      # defaults
      #

      self.cache = {}
      self.enablement_by_type = {}
      self.module_load_error_by_reference_name = {}
      self.module_paths = []
      self.module_set_by_type = {}

      #
      # from arguments
      #

      self.framework = framework

      types.each { |type|
        init_module_set(type)
      }

      super(nil)
    end

    def register_type_extension(type, ext)
    end

    protected

    #
    # This method automatically subscribes a module to whatever event providers
    # it wishes to monitor.  This can be used to allow modules to automatically
    # execute or perform other tasks when certain events occur.  For instance,
    # when a new host is detected, other aux modules may wish to run such
    # that they can collect more information about the host that was detected.
    #
    def auto_subscribe_module(mod)
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
      if (mod.include?(ExploitEvent) == true)
        framework.events.add_exploit_subscriber((inst) ? inst : (inst = mod.new))
      end

      #
      # Session event subscriber check
      #
      if (mod.include?(SessionEvent) == true)
        framework.events.add_session_subscriber((inst) ? inst : (inst = mod.new))
      end
    end

    attr_accessor :modules # :nodoc:
  end
end
