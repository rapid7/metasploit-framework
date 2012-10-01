# -*- coding: binary -*-
require 'msf/core'
require 'fastlib'
require 'pathname'

module Msf

  #
  # Define used for a place-holder module that is used to indicate that the
  # module has not yet been demand-loaded. Soon to go away.
  #
  SymbolicModule = "__SYMBOLIC__"

  ###
  #
  # A module set contains zero or more named module classes of an arbitrary
  # type.
  #
  ###
  class ModuleSet < Hash
    include Framework::Offspring

    # Wrapper that detects if a symbolic module is in use.  If it is, it creates an instance to demand load the module
    # and then returns the now-loaded class afterwords.
    def [](name)
      if (super == SymbolicModule)
        create(name)
      end

      super
    end

    # Create an instance of the supplied module by its name
    #
    def create(name)
      klass = fetch(name, nil)
      instance = nil

      # If there is no module associated with this class, then try to demand
      # load it.
      if klass.nil? or klass == SymbolicModule
        # If we are the root module set, then we need to try each module
        # type's demand loading until we find one that works for us.
        if module_type.nil?
          MODULE_TYPES.each { |type|
            framework.modules.demand_load_module(type, name)
          }
        else
          framework.modules.demand_load_module(module_type, name)
        end

        recalculate

        klass = get_hash_val(name)
      end

      # If the klass is valid for this name, try to create it
      if klass and klass != SymbolicModule
        instance = klass.new
      end

      # Notify any general subscribers of the creation event
      if instance
        self.framework.events.on_module_created(instance)
      end

      return instance
    end

    #
    # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
    #    "can't add a new key into hash during iteration"
    #
    def each(&block)
      list = []
      self.keys.sort.each do |sidx|
        list << [sidx, self[sidx]]
      end
      list.each(&block)
    end

    #
    # Enumerates each module class in the set.
    #
    def each_module(opts = {}, &block)
      demand_load_modules

      self.mod_sorted = self.sort

      each_module_list(mod_sorted, opts, &block)
    end

    #
    # Custom each_module filtering if an advanced set supports doing extended
    # filtering.  Returns true if the entry should be filtered.
    #
    def each_module_filter(opts, name, entry)
      return false
    end

    #
    # Enumerates each module class in the set based on their relative ranking
    # to one another.  Modules that are ranked higher are shown first.
    #
    def each_module_ranked(opts = {}, &block)
      demand_load_modules

      self.mod_ranked = rank_modules

      each_module_list(mod_ranked, opts, &block)
    end

    #
    # Forces all modules in this set to be loaded.
    #
    def force_load_set
      each_module { |name, mod| }
    end

    #
    # Initializes a module set that will contain modules of a specific type and
    # expose the mechanism necessary to create instances of them.
    #
    def initialize(type = nil)
      #
      # Defaults
      #
      self.ambiguous_module_reference_name_set = Set.new
      # Hashes that convey the supported architectures and platforms for a
      # given module
      self.mod_arch_hash     = {}
      self.mod_platform_hash = {}
      self.mod_sorted        = nil
      self.mod_ranked        = nil
      self.mod_extensions    = []

      #
      # Arguments
      #
      self.module_type = type
    end

    attr_reader   :module_type

    #
    # Gives the module set an opportunity to handle a module reload event
    #
    def on_module_reload(mod)
    end

    #
    # Whether or not recalculations should be postponed.  This is used from the
    # context of the each_module_list handler in order to prevent the demand
    # loader from calling recalc for each module if it's possible that more
    # than one module may be loaded.  This field is not initialized until used.
    #
    attr_accessor :postpone_recalc


    #
    # Dummy placeholder to relcalculate aliases and other fun things.
    #
    def recalculate
    end

    #
    # Checks to see if the supplied module name is valid.
    #
    def valid?(name)
      create(name)
      (self[name]) ? true : false
    end

    protected

    #
    # Adds a module with a the supplied name.
    #
    def add_module(mod, name, modinfo = nil)
      # Set the module's name so that it can be referenced when
      # instances are created.
      mod.framework = framework
      mod.refname   = name
      mod.file_path = ((modinfo and modinfo['files']) ? modinfo['files'][0] : nil)
      mod.orig_cls  = mod

      cached_module = self[name]

      if (cached_module and cached_module != SymbolicModule)
        ambiguous_module_reference_name_set.add(name)

        wlog("The module #{mod.refname} is ambiguous with #{self[name].refname}.")
      else
        self[name] = mod
      end

      mod
    end

    #
    # Load all modules that are marked as being symbolic.
    #
    def demand_load_modules
      # Pre-scan the module list for any symbolic modules
      self.each_pair { |name, mod|
        if (mod == SymbolicModule)
          self.postpone_recalc = true

          mod = create(name)

          next if (mod.nil?)
        end
      }

      # If we found any symbolic modules, then recalculate.
      if (self.postpone_recalc)
        self.postpone_recalc = false

        recalculate
      end
    end

    #
    # Enumerates the modules in the supplied array with possible limiting
    # factors.
    #
    def each_module_list(ary, opts, &block)
      ary.each { |entry|
        name, mod = entry

        # Skip any lingering symbolic modules.
        next if (mod == SymbolicModule)

        # Filter out incompatible architectures
        if (opts['Arch'])
          if (!mod_arch_hash[mod])
            mod_arch_hash[mod] = mod.new.arch
          end

          next if ((mod_arch_hash[mod] & opts['Arch']).empty? == true)
        end

        # Filter out incompatible platforms
        if (opts['Platform'])
          if (!mod_platform_hash[mod])
            mod_platform_hash[mod] = mod.new.platform
          end

          next if ((mod_platform_hash[mod] & opts['Platform']).empty? == true)
        end

        # Custom filtering
        next if (each_module_filter(opts, name, entry) == true)

        block.call(name, mod)
      }
    end

    attr_accessor :ambiguous_module_reference_name_set
    attr_accessor :mod_arch_hash
    attr_accessor :mod_extensions
    attr_accessor :mod_platform_hash
    attr_accessor :mod_ranked
    attr_accessor :mod_sorted
    attr_writer   :module_type
    attr_accessor :module_history

    #
    # Ranks modules based on their constant rank value, if they have one.
    #
    def rank_modules
      self.mod_ranked = self.sort { |a, b|
        a_name, a_mod = a
        b_name, b_mod = b

        # Dynamically loads the module if needed
        a_mod = create(a_name) if a_mod == SymbolicModule
        b_mod = create(b_name) if b_mod == SymbolicModule

        # Extract the ranking between the two modules
        a_rank = a_mod.const_defined?('Rank') ? a_mod.const_get('Rank') : NormalRanking
        b_rank = b_mod.const_defined?('Rank') ? b_mod.const_get('Rank') : NormalRanking

        # Compare their relevant rankings.  Since we want highest to lowest,
        # we compare b_rank to a_rank in terms of higher/lower precedence
        b_rank <=> a_rank
      }
    end
  end
end
