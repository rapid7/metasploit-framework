class Metasploit::Framework::Module::Cache < Metasploit::Model::Base

  #
  # CONSTANTS
  #

  # `Class#name` for classes in {path_loader_classes} by default.
  PATH_LOADER_CLASS_NAMES = [
      'Metasploit::Framework::Module::Path::Loader::Directory'
  ]

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

  # Returns the {Metasploit::Framework::Module::Path::Loader::Base loader} that
  # can load the given module_path.
  #
  # @return [Metasploit::Framework::Module::Path::Loader::Base]
  def module_path_loader(module_path)
    path_loaders.find { |path_loader|
      path_loader.loadable?(module_path)
    }
  end

  delegate :module_type_enabled?, to: :module_manager

  # Path loader classes to initiate in {#path_loaders}
  #
  # @return [Array<Class<Metasploit::Framework::Module::Path::Loader>>]
  def self.path_loader_classes
    @path_loader_classes ||= PATH_LOADER_CLASS_NAMES.map(&:constantize)
  end

  # Path loaders.
  #
  # @return [Array<Metasploit::Framework::Module::Path::Loader>>]
  def path_loaders
    @path_loaders ||= self.class.path_loader_classes.collect { |path_loader_class|
      path_loader = path_loader_class.new(cache: self)
      path_loader.valid!

      path_loader
    }
  end

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
  # @return [void]
  # @raise (see Metasploit::Framework::Module::PathSet::Base#superset!)
  def prefetch(options={})
    options.assert_valid_keys(:only)

    module_paths = Array.wrap(options[:only])

    if module_paths.blank?
      module_paths = path_set.all
    else
      path_set.superset!(module_paths)
    end

    module_paths.each do |module_path|
      loader = module_path_loader(module_path)
      loader.load_module_path(module_path)
    end
  end
end