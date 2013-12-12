class Metasploit::Framework::Module::Class::Load::Base < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] cache
  #   The module cache that should be written in {#metasploit_class} if the `Metasploit::Model::Module::Class#ancestors`
  #   need to be loaded.
  #
  #   @return [Metasploit::Framework::Module::Cache]
  attr_accessor :cache

  # @!attribute [rw] module_class
  #   The `Metasploit::Model::Module::Class` describing the {#metasploit_class} to be loaded.
  #
  #   @return [Metasploit::Model::Module::Class]
  attr_accessor :module_class

  #
  # Validations
  #

  validates :cache,
            presence: true
  validates :module_class,
            presence: true
  validates :metasploit_class,
            presence: true,
            unless: :loading_context?

  #
  # Methods
  #

  def metasploit_class
    metasploit_class = nil

    if valid?(:loading)
      inherit = false
      retrying = false

      begin
        child_constant = self.class.parent_constant.const_get relative_constant_name, inherit
      rescue NameError
        unless retrying
          written = true

          module_ancestors.each do |module_ancestor|
            module_ancestor_load = Metasploit::Framework::Module::Ancestor::Load.new(module_ancestor: module_ancestor)

            written &= cache.write_module_ancestor_load(module_ancestor_load)
          end

          if written
            retrying = true
            retry
          end
        end
      else
        metasploit_class = metasploit_class_from_child_constant(child_constant)
      end
    end

    metasploit_class
  end

  # @!method module_type
  #   The type of {#module_class} being loaded.
  #
  #   @return [String] an element of `Metasploit::Model::Module::Type::ALL`.
  #   @return [nil] of {#module_class} is `nil`.
  delegate :module_type,
           # allow nil to work with validation
           allow_nil: true,
           to: :module_class

  def module_ancestors
    if module_class
      module_class.ancestors
    end
  end

  def self.module_ancestor_partial_name(module_ancestor)
    "RealPathSha1HexDigest#{module_ancestor.real_path_sha1_hex_digest}"
  end

  def module_ancestor_partial_name_by_payload_type
    @module_ancestor_partial_name_by_payload_type ||= module_ancestors.each_with_object({}) { |module_ancestor, module_ancestor_partial_name_by_payload_type|
      module_ancestor_partial_name_by_payload_type[module_ancestor.payload_type] = self.class.module_ancestor_partial_name(module_ancestor)
    }
  end

  protected

  def metasploit_class_from_child_constant(child_constant)
    raise NotImplementedError
  end

  def self.parent_constant
    raise NotImplementedError
  end

  def relative_constant_name
    raise NotImplementedError
  end

  private

  # Whether the current `#validation_context` is `:loading`.
  #
  # @return [true] if `#validation_context` is `:loading`.
  # @return [false] otherwise
  def loading_context?
    validation_context == :loading
  end
end