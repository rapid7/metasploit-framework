# -*- coding: binary -*-
require 'msf/base/simple'
require 'msf/base/simple/framework/module_paths'

module Msf
module Simple

###
#
# This class wraps the framework-core supplied Framework class and adds some
# helper methods for analyzing statistics as well as other potentially useful
# information that is directly necessary to drive the framework-core.
#
###
module Framework
  include Msf::Simple::Framework::ModulePaths

  ###
  #
  # Extends the framework.plugins class instance to automatically check in
  # the framework plugin's directory.
  #
  ###
  module PluginManager

    #
    # Loads the supplied plugin by checking to see if it exists in the
    # framework default plugin path as necessary.
    #
    def load(path, opts = {})
      def_path = Msf::Config.plugin_directory + File::SEPARATOR + path

      if (File.exist?(def_path) or File.exist?(def_path + ".rb"))
        super(def_path, opts)
      else
        super
      end
    end

  end

  #
  # We extend modules when we're created, and we do it by registering a
  # general event subscriber.
  #
  include GeneralEventSubscriber

  #
  # Simplifies module instances when they're created.
  #
  def on_module_created(instance)
    Msf::Simple::Framework.simplify_module(instance)
  end

  ModuleSimplifiers =
    {
      Msf::MODULE_ENCODER => Msf::Simple::Encoder,
      Msf::MODULE_EXPLOIT => Msf::Simple::Exploit,
      Msf::MODULE_NOP     => Msf::Simple::Nop,
      Msf::MODULE_PAYLOAD => Msf::Simple::Payload,
      Msf::MODULE_AUX     => Msf::Simple::Auxiliary,
      Msf::MODULE_POST    => Msf::Simple::Post,
      Msf::MODULE_EVASION => Msf::Simple::Evasion
    }

  # Create a simplified instance of the framework.  This routine takes a hash
  # of parameters as an argument.  This hash can contain:
  #
  # @param opts [Hash{String => Object}]
  # @option opts (see simplify)
  # @return [Msf::Simple::Frameworkt s]
  def self.create(opts = {})
    framework = Msf::Framework.new(opts)
    return simplify(framework, opts)
  end

  # @note If `opts['ConfigDirectory']` is set, then `Msf::Config::Defaults['ConfigDirectory']` will be updated to
  #   `opts['ConfigDirectory']`.
  #
  # Extends a framework object that may already exist.
  #
  # @param framework [Msf::Framework, Msf::Simple::Framework] framework to simplify
  # @param opts [Hash{String => Object}]
  # @option opts [#call] 'OnCreateProc' Proc to call after {#init_simplified}.  Will be passed `framework`.
  # @option opts [String] 'ConfigDirectory'  Directory where configuration is saved.  The `~/.msf4` directory.
  # @option opts [Boolean] 'DisableLogging' (false) `true` to disable `Msf::Logging.init`
  # @option opts [Boolean] 'DeferModuleLoads' (false) `true` to disable `framework.init_module_paths`.
  # @return [Msf::Simple::Framework] `framework`
  def self.simplify(framework, opts)

    # If the framework instance has not already been extended, do it now.
    if (framework.kind_of?(Msf::Simple::Framework) == false)
      framework.extend(Msf::Simple::Framework)
      framework.plugins.extend(Msf::Simple::Framework::PluginManager)
    end

    # Initialize the simplified framework
    framework.init_simplified()

    # Call the creation procedure if one was supplied
    if (opts['OnCreateProc'])
      opts['OnCreateProc'].call(framework)
    end

    # Change to a different configuration path if requested
    if opts['ConfigDirectory']
      Msf::Config::Defaults['ConfigDirectory'] = opts['ConfigDirectory']
    end

    # Initialize configuration and logging
    Msf::Config.init
    Msf::Logging.init unless opts['DisableLogging']

    # Load the configuration
    framework.load_config

    # Register the framework as its own general event subscriber in this
    # instance
    framework.events.add_general_subscriber(framework)

    unless opts['DeferModuleLoads']
      framework.init_module_paths
    end

    return framework
  end

  #
  # Simplifies a module instance if the type is supported by extending it
  # with the simplified module interface.
  #
  def self.simplify_module(instance, load_saved_config = true)
    if ((ModuleSimplifiers[instance.type]) and
        (instance.class.include?(ModuleSimplifiers[instance.type]) == false))
      instance.extend(ModuleSimplifiers[instance.type])

      instance.init_simplified(load_saved_config)
    end
  end


  ##
  #
  # Simplified interface
  #
  ##

  #
  # Initializes the simplified interface.
  #
  def init_simplified
    self.stats = Statistics.new(self)
    self.ready = Set.new
    self.running = Set.new
    self.results = Hash.new
  end

  #
  # Loads configuration, populates the root datastore, etc.
  #
  def load_config
    self.datastore.from_file(Msf::Config.config_file, 'framework/core')
  end

  #
  # Saves the module's datastore to the file
  #
  def save_config
    self.datastore.to_file(Msf::Config.config_file, 'framework/core')
  end

  #
  # Statistics.
  #
  attr_reader :stats

  #
  # Boolean indicating whether the cache is initialized yet
  #
  attr_reader :cache_initialized

  #
  # Thread of the running rebuild operation
  #
  attr_reader :cache_thread

  #
  # {Set<String>} of module run/check UUIDs waiting to be kicked off
  #
  attr_reader :ready

  #
  # {Hash<String,Hash>} of module run/check results, by UUID. Successful runs
  # look like `{result: check_code}` and errors like `{error: message}`.
  #
  attr_reader :results

  #
  # {Set<String>} of module run/check UUIDs currently in progress
  #
  attr_reader :running
  attr_writer :cache_initialized # :nodoc:
  attr_writer :cache_thread # :nodoc:


protected

  attr_writer :ready # :nodoc:
  attr_writer :results # :nodoc:
  attr_writer :running # :nodoc:
  attr_writer :stats # :nodoc:

end

end
end

