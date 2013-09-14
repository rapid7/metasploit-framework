# Responsible for loading a `Metasploit::Model::Module::Path` for {Metasploit::Framework::Module::Cache}.
#
# @example Loading only changed `Metasploit::Model::Module::Ancestors` in {#module_path}.
#   load = Metasploit::Framework::Module::Path::Load.new(cache: cache, module_path: module_path)
#   load.valid?
#
# @example Loading all `Metasploit::Model::Module::Ancestors` in {#module_path}.
#   load = Metasploit::Framework::Module::Path::Load.new(cache: cache, changed: true, module_path: module_path)
#   load.valid?
class Metasploit::Framework::Module::Path::Load < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] cache
  #   The module cache that is using this loader.
  #
  #   @return [Metasploit::Framework::Module::Cache]
  attr_accessor :cache

  # @!attribute [rw] changed
  #   Whether `Metasploit::Model::Module::Ancestors` under {#module_path} should be assumed to be changed.  Only changed
  #   `Metasploit::Model::Module::Ancestors` are loaded.
  #
  #   @return [Boolean]
  attr_writer :changed

  # @!attribute [rw] module_path
  #   The module_path being loaded
  #
  #   @return [Metasploit::Model::Module::Path]
  attr_accessor :module_path

  #
  #
  # Validations
  #
  #

  #
  # Method validations
  #

  validate :module_ancestor_loads_valid,
           unless: :loading_context?

  #
  # Attribute validations
  #

  validates :cache,
            presence: true
  validates :changed,
            inclusion: {
                in: [
                    false,
                    true
                ]
            }
  validates :module_path,
            :presence => true

  #
  # Methods
  #

  # Whether `Metasploit::Model::Module::Ancestors` under {#module_path} should be assumed to be changed.  Only changed
  # `Metasploit::Model::Module::Ancestors` are loaded.
  #
  # @return [Boolean]
  # @see Mdm::Module::Path#each_changed_module_ancestor
  def changed
    unless instance_variable_defined? :@changed
      # default to false to match `Mdm::Module::Ancestor#changed_module_ancestor_from_real_path`.
      @changed = false
    end

    @changed
  end

  # Loads all of the `Metasploit::Model::Module::Ancestors` from the supplied
  # module path.
  #
  # @param module_path [Metasploit::Model::Module::Path] module_path Path under
  #   which there are module ancestors
  # @param options [Hash{Symbol => Object}]
  # @option options [Boolean] :changed (false) if `true`, assume the
  #   `Mdm::Module::Ancestor#real_path_modified_at` and
  #   `Mdm::Module::Ancestor#real_path_sha1_hex_digest` have changed and all
  #   `Mdm::Module::Ancestor` should be returned.
  # @option options [Boolean] :force (false) Whether to force loading of
  #   the module ancestor even if the module ancestor has not changed.
  # @return [Array<Metasploit::Framework::Module::Ancestor::Load>] {#module_ancestor_loads}
  # @return [nil] if this load is not valid for the `:load_module_path` context
  def module_ancestor_loads
    unless instance_variable_defined? :@module_ancestor_loads
      if valid?(:loading)
        @module_ancestor_loads = []

        module_path.each_changed_module_ancestor(changed: changed) do |module_ancestor|
          module_ancestor_load = Metasploit::Framework::Module::Ancestor::Load.new(module_ancestor: module_ancestor)
          @module_ancestor_loads << module_ancestor_load
        end
      end
    end

    @module_ancestor_loads
  end

  # Set of all `Metasploit::Model::Module::Ancestor#module_types` supported by `Metasploit::Model::Module::Ancestors`
  # loaded by {#module_ancestor_loads}.  If a {Metasploit::Framework::Module::Ancestor::Load} is invalid, then it's
  # {Metasploit::Framework::Module::Ancestor::Load#module_ancestor}'s `Metasploit::Model::Module::Ancestor#module_type`
  # is not included in the set as an invalid {Metasploit::Framework::Module::Ancestor::Load} indicates the
  # `Metasploit::Model::Module::Ancestor#contents` were not successfully evaluate into a ruby `Module`.
  #
  # @return [Set<String>]
  def module_type_set
    @module_type_set ||= module_ancestor_loads.each_with_object(Set.new) { |module_ancestor_load, set|
      if module_ancestor_load.valid?
        set.add(module_ancestor_load.module_ancestor.module_type)
      end
    }
  end

  protected

  delegate :module_type_enabled?, to: :cache

  private

  # Whether this load is in the `:module_ancestor_loads` validation context.
  #
  # @example Validating load in :module_ancestor_loads validation context
  #   load.valid?(:module_ancestor_loads)
  #
  # @return [Boolean]
  def loading_context?
    validation_context == :loading
  end

  # Validates whether all {#module_ancestor_loads} are valid.
  #
  # @return [void]
  def module_ancestor_loads_valid
    unless module_ancestor_loads.blank?
      unless module_ancestor_loads.all?(&:valid?)
        errors.add(:module_ancestor_loads, :invalid)
      end
    end
  end
end
