# Loads a `Metasploit::Model::Module::Ancestor` and keeps any load errors as validation errors.
class Metasploit::Framework::Module::Ancestor::Load < Metasploit::Model::Base
  include Metasploit::Framework::Module::Ancestor::Load::NamespaceModule

  #
  # Attributes
  #

  # @!attribute [rw] module_ancestor
  #   The module ancestor being loaded.
  #
  #   @return [Metasploit::Model::Module::Ancestor]
  attr_accessor :module_ancestor

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :metasploit_module_valid,
           unless: :loading_context?
  validate :module_ancestor_valid

  #
  # Attribute Validations
  #

  validates :metasploit_module,
            unless: :loading_context?,
            presence: true
  validates :module_ancestor,
            presence: true

  #
  # Methods
  #

  # `Metasploit<n>` ruby `Module` declared in {#module_ancestor module_ancestor's}
  # `Metasploit::Model::Module::Ancestor#contents`.
  #
  # @return [Module]
  def metasploit_module
    namespace_module = self.namespace_module

    if namespace_module
      namespace_module.metasploit_module
    else
      nil
    end
  end

  # @note Calling this method (either directly or by validating this module ancestor load) will both declare the
  #   namespace `Module` and evaluate `Metasploit::Model::Module::Ancestor#contents` within that `Module`, so at the end
  #   of the call, assuming the `Modules` are valid and there are no exceptions, both `Modules` will be bound to
  #   constants in this processes memory space.
  # @note Once this method is called (after being valid for loading), its results are memoized to reflect that there
  #   were errors with the `Metasploit::Model::Module::Ancestor#contents` or the constants now exist in the memory
  #   space. To reload the `Metasploit::Model::Module::Ancestor` for a change to `Metasploit::Model::Module::Ancestor`,
  #   create a new {Metasploit::Framework::Module::Ancestor::Load}.
  #
  # Ruby `Module` that wraps {#metasploit_module} to prevent it from overriding the `Metasploit<n>` from other
  # `Metapsloit::Model::Module::Ancestor#contents`.
  #
  # @return [nil] if this module ancestor load is not valid for loading.
  # @return [nil] if {#module_ancestor} could not be
  #   {Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval evaluated} into the namespace `Module`.
  # @return [Module] otherwise
  def namespace_module
    unless instance_variable_defined? :@namespace_module
      if valid?(:loading)
        namespace_module_transaction(module_ancestor) do |module_ancestor, namespace_module|
          commit = false
          @namespace_module = nil

          if namespace_module.module_ancestor_eval(module_ancestor)
            @namespace_module = namespace_module

            commit = true
          else
            # since namespace_module is being reverted, we need to keep a copy of the validation errors without a copy
            # of namespace_module.
            namespace_module.valid?
            @namespace_module_errors = namespace_module.errors
          end

          commit
        end
      end
    end

    @namespace_module
  end

  # Caches {#namespace_module} validation errors in case {#namespace_module} is `nil` because its construction or
  # the {#metapsloit_module} construction is invalid.
  #
  # @return [ActiveModel::Errors]
  def namespace_module_errors
    unless instance_variable_defined? :@namespace_module_errors
      @namespace_module_errors = nil
      namespace_module = self.namespace_module

      if namespace_module
        @namespace_module_errors = namespace_module.errors
      end
    end

    @namespace_module_errors
  end

  private

  # Whether the current `#validation_context` is `:loading`.
  #
  # @return [true] if `#validation_context` is `:loading`.
  # @return [false] otherwise
  def loading_context?
    validation_context == :loading
  end

  # Validates that {#metasploit_module} is valid, but only if {#metasploit_module} is not `nil`.
  #
  # @return [void]
  def metasploit_module_valid
    if metasploit_module and metasploit_module.invalid?(validation_context)
      errors.add(:metasploit_module, :invalid)
    end
  end

  # Validates that {#module_ancestor} is valid, but only if {#module_ancestor} is not `nil`.
  #
  # @return [void]
  def module_ancestor_valid
    # allow the presence validation to handle it being nil
    if module_ancestor and module_ancestor.invalid?(validation_context)
      errors.add(:module_ancestor, :invalid)
    end
  end
end