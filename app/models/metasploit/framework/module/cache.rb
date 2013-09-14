class Metasploit::Framework::Module::Cache < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] module_manager
  #   The module manager using this cache.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  #
  # Validations
  #

  validates :module_manager,
            :presence => true

  #
  # Methods
  #

  delegate :module_type_enabled?, to: :module_manager

  # Set of paths this cache using to load `Metasploit::Model::Ancestors`.
  #
  # @return [Metasploit::Framework::Module::PathSet::Base]
  def path_set
    unless instance_variable_defined? :@path_set
      path_set = Metasploit::Framework::Module::PathSet::Database.new(
          cache: self
      )
      path_set.valid!

      @path_set = path_set
    end

    @path_set
  end

  # Checks that this cache is up-to-date by scanning the
  # `Metasploit::Model::Path#real_path` of each `Metasploit::Module::Path` in
  # {#path_set} for updates to `Metasploit::Model::Module::Ancestors`.
  #
  # @param options [Hash]
  # @option options [nil, Metasploit::Model::Module::Path, Array<Metasploit::Model::Module::Path>] :only only prefetch
  #   the given module paths.  If :only is not given, then all module paths in
  #   {#path_set} will be prefetched.
  # @return [Array<Metasploit::Framework::Module::Path::Load>]
  # @raise (see Metasploit::Framework::Module::PathSet::Base#superset!)
  def prefetch(options={})
    options.assert_valid_keys(:only)

    module_paths = Array.wrap(options[:only])

    if module_paths.blank?
      module_paths = path_set.all
    else
      path_set.superset!(module_paths)
    end

    module_path_loads = []

    # TODO generalize to work with or without ActiveRecord for in-memory models
    ActiveRecord::Base.connection_pool.with_connection do
      module_path_loads = module_paths.collect do |module_path|
        Metasploit::Framework::Module::Path::Load.new(
            cache: self,
            module_path: module_path
        )
      end

      deferred_recalculation_module_type_set = module_path_loads.each_with_object(Set.new) { |module_path_load, set|
        set.merge(module_path_load.module_type_set)
      }

      deferred_recalculation_module_type_set.each do |module_type|
        module_set = module_manager.module_set(module_type)
        module_set.recalculate
      end
    end

    module_path_loads
  end
end