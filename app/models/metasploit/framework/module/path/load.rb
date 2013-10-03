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

  # @note The yielded {Metasploit::Framework::Module::Ancestor::Load} will not have loaded the ruby `Module` into this
  #   process until {Metasploit::Framework::Module::Ancestor::Load#metasploit_module} is called either directly or
  #   indirectly by {Metasploit::Framework::Module::Ancestor::Load#namespace_module} or validating the
  #   {Metasploit::Framework::Module::Ancestor::Load}.
  #
  # @overload each_module_ancestor_load(options={}, &block)
  #   @note Will not yield anything if this module path load is invalid.
  #
  #   Yields {Metasploit::Framework::Module::Ancestor::Load} for each changed {Metasploit::Model::Module::Ancestor}
  #   under {#module_path}.
  #
  #   @yield [module_ancestor_load]
  #   @yieldparam module_ancestor_load [Metasploit::Framework::Module::Ancestor::Load] will load
  #     {Metasploit::Model::Module::Ancestor#contents} into memory if validated or if
  #     {Metasploit::Framework::Module::Ancestor::Load#namespace_module} or
  #     {Metasploit::Framework::Module::Ancestor::Load#metasploit_module} is called directly.
  #   @yieldreturn [void]
  #   @return [void]
  #
  # @overload each_module_ancestor_load(options={})
  #   Returns enumerator that yields a {Metasploit::Framework::Module::Ancestor::Load} for each changed
  #   {Metasploit::Model::Module::Ancestor} under {#module_path}.
  #
  #   @return [Enumerator]
  #
  # @see Mdm::Module::Path#each_changed_module_ancestor
  def each_module_ancestor_load
    unless block_given?
      to_enum(__method__)
    else
      if valid?
        module_path.each_changed_module_ancestor(changed: changed) do |module_ancestor|
          module_ancestor_load = Metasploit::Framework::Module::Ancestor::Load.new(module_ancestor: module_ancestor)

          yield module_ancestor_load
        end
      end
    end
  end

  protected

  delegate :module_type_enabled?, to: :cache
end
