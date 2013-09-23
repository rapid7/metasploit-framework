require 'msf/core/module_manager'

module Msf::Framework::Modules
  extend ActiveSupport::Concern

  included do
    #
    # Validations
    #

    validates :module_types,
              module_types: true
  end

  #
  # Attributes
  #

  # @!attribute [rw] module_types
  #   Types of modules that should be loaded by this framework.
  #
  #   @return [Array<String>] subset of `Metasploit::Model::Module::Type::ALL`

  #
  # Methods
  #

  # Types of modules that should be loaded in this framework.
  #
  # @return [Array<String>] subset of `Metasploit::Model::Module::Type::ALL`.  Defaults to
  #   `Metasploit::Model::Module::Type::ALL`.
  def module_types
    @module_types ||= Metasploit::Model::Module::Type::ALL
  end
  attr_writer :module_types

  # Modules that are or can be be loaded by this framework.
  #
  # @return [Msf::ModuleManager]
  # @raise [Metasploit::Model::Invalid] if module manager is invalid
  def modules
    synchronize {
      unless instance_variable_defined? :@modules
        module_manager = Msf::ModuleManager.new(framework: self)
        module_manager.valid!

        @modules = module_manager
      end

      @modules
    }
  end

  Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE.each_value do |directory|
    delegate directory,
             to: :modules
  end
end