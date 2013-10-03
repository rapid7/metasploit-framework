# Concern for behavior that all namespace modules that wrap
# `Metasploit::Model::Module::Ancestor` reified in ruby `Classes` and `Modules`
# must support like version checking and grabbing the version
# specific-Metasploit* class.
module Metasploit::Framework::Module::Ancestor::Namespace
  extend ActiveSupport::Concern

  include Metasploit::Framework::ProxiedValidation

  #
  # Attributes
  #

  # @!attribute [r] module_ancestor_eval_exception
  #   Exception raised in {#module_ancestor_eval}.
  #
  #   @return [nil] if {#module_ancestor_eval} has not run yet.
  #   @return [nil] if no exception was raised
  #   @return [Exception] if exception was raised
  attr_reader :module_ancestor_eval_exception

  # @!attribute [rw] module_type
  #   The `Metasploit::Model::Module::Ancestor#module_type`.
  #
  #   @return [String] element of `Metasploit::Model::Module::Type::ALL`.
  attr_accessor :module_type

  # @!attribute [rw] payload_type
  #   The `Metasploit::Model::Module::Ancestor#payload_type`.  Only set if {#module_type} is
  #   `Metasploit::Model::Module::Type::PAYLOAD`.
  #
  #   @return [nil] if {#module_type} is `Metasploit::Model::Module::Type::PAYLOAD`.
  #   @return [String] element of `Metasploit::Model::Module::Ancestor::PAYLOAD_TYPES`
  attr_accessor :payload_type

  # @!attribute [rw] real_path_sha1_hex_digest
  #   The `Metasploit::Model::Module::Ancestor#real_path_sha1_hex_digest`.  Used to look up
  #   `Metasploit::Module::Module::Ancestor`.
  #
  #   @return [String]
  attr_accessor :real_path_sha1_hex_digest

  #
  # Methods
  #

  # Returns the Metasploit<n> module from the module_evalled content.
  #
  # @note The `Metasploit::Model::Module::Ancestor#contents` must be module_evalled into this namespace module before
  #   the return of {#metasploit_module} is valid.
  #
  # @return [Msf::Module] if a Metasploit<n> `Module` exists in this module
  # @return [nil] if such as `Module` is not defined.
  def metasploit_module
    unless instance_variable_defined? :@metasploit_module
      @metasploit_module = nil
      # don't search ancestors for the metasploit module
      inherit = false

      Msf::Framework::Major.downto(1) do |major|
        metasploit_constant_name = "Metasploit#{major}"

        if const_defined?(metasploit_constant_name, inherit)
          metasploit_constant = const_get(metasploit_constant_name)

          # Classes and Modules are Modules
          if metasploit_constant.is_a? Module
            @metasploit_module = metasploit_constant
            @metasploit_module.extend Metasploit::Framework::Module::Ancestor::MetasploitModule
          end

          break
        end
      end
    end

    @metasploit_module
  end

  def minimum_api_version
    required_versions[1]
  end

  def minimum_core_version
    required_versions[0]
  end

  # Evaluates `module_ancestor`'s `Metasploit::Model::Module::Ancestor` in the lexical scope of the `Module` in which
  # this module is `extend`ed.
  #
  # @param module_ancestor [Metasploit::Model::Module::Ancestor, #contents, #real_path]
  # @return [true] if `module_ancestor` was successfully evaluated into this namespace module.
  # @return [false] otherwise.
  def module_ancestor_eval(module_ancestor)
    success = false

    begin
      module_eval_with_lexical_scope(module_ancestor.contents, module_ancestor.real_path)
    rescue Interrupt
      # handle Interrupt as pass-through unlike other Exceptions so users can bail with Ctrl+C
      raise
    rescue Exception => error
      @module_ancestor_eval_exception = error
    else
      if valid?
        metasploit_module.cache_module_ancestor(module_ancestor)

        # TODO log module_ancestor.errors
        if module_ancestor.persisted?
          success = true
        end
      end
    end

    success
  end

  # Return whether this forms part of a payload (either a single, stage, or stager).
  #
  # @return [true] if {#module_type} is `Metasploit::Model::Module::Type::PAYLOAD`
  # @return [false] otherwise
  def payload?
    module_type == Metasploit::Model::Module::Type::PAYLOAD
  end

  def required_versions
    unless instance_variable_defined? :@required_versions
      if const_defined?(:RequiredVersions)
        @required_versions = const_get(:RequiredVersions)
      else
        @required_versions = [nil, nil]
      end
    end

    @required_versions
  end

  def validation_proxy_class
    Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy
  end
end

