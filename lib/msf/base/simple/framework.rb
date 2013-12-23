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

      if (File.exists?(def_path) or File.exists?(def_path + ".rb"))
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

  MODULE_SIMPLIFIER_BY_MODULE_TYPE = {
      Metasploit::Model::Module::Type::ENCODER => Msf::Simple::Encoder,
      Metasploit::Model::Module::Type::EXPLOIT => Msf::Simple::Exploit,
      Metasploit::Model::Module::Type::NOP     => Msf::Simple::Nop,
      Metasploit::Model::Module::Type::PAYLOAD => Msf::Simple::Payload,
      Metasploit::Model::Module::Type::AUX     => Msf::Simple::Auxiliary,
      Metasploit::Model::Module::Type::POST    => Msf::Simple::Post,
  }

  # Create a simplified instance of the framework.
  #
  # @param options [Hash{Symbol => Object}]
  # @option options [Boolean] 'DisableDatabase' DEPRECATED, use :database_disabled option.
  # @option options [Boolean] :database_disabled (false) Disable the {Msf::Framework#db framework database manager}.
  # @option options [Array<String>, nil] :module_types A subset of `Metasploit::Model::Module::Type:ALL`.
  # @return [Msf::Simple::Framework]
  # @raise [Metasploit::Model::Invalid] unless :module_types is a subset of `Metasploit::Model::Module::Type::ALL`.
  # @raise [Metasploit::Model::Invalid] unless :module_types has at least one module type in it.
  def self.create(options = {})
    # force to Boolean
    database_disabled = !!options.fetch('DisableDatabase', false)
    database_disabled = options.fetch(:database_disabled, database_disabled)

    framework = Msf::Framework.new(
        database_disabled: database_disabled,
        module_types: options[:module_types]
    )
    framework.valid!

    simplify(framework, options)
  end

  #
  # Extends a framework object that may already exist.
  #
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
    Msf::Logging.init

    # Load the configuration
    framework.load_config

    # Register the framework as its own general event subscriber in this
    # instance
    framework.events.add_general_subscriber(framework)

    unless opts['DeferModuleLoads']
      framework.add_module_paths
    end

    return framework
  end

  #
  # Simplifies a module instance if the type is supported by extending it
  # with the simplified module interface.
  #
  def self.simplify_module(instance, load_saved_config = true)
    simplifier = MODULE_SIMPLIFIER_BY_MODULE_TYPE[instance.module_type]

    if simplifier && !instance.class.include?(simplifier)
      instance.extend simplifier

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
  attr_writer :cache_initialized # :nodoc:
  attr_writer :cache_thread # :nodoc:


protected

  attr_writer :stats # :nodoc:

end

end
end

