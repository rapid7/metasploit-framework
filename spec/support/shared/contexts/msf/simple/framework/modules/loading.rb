shared_context 'Msf::Simple::Framework#modules loading' do
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  #
  # Methods
  #

  # @param modules_path [String] path to `modules` directory from which to load ancestor reference names.
  def loader_for_modules_path(modules_path)
    loader = framework.modules.send(:loaders).find { |loader|
      loader.loadable?(modules_path)
    }

    # Override load_error so that rspec will print it instead of going to framework log
    def loader.load_error(module_path, error)
      raise error
    end

    loader
  end

  def expect_to_load_module_ancestor(options={})
    options.assert_valid_keys(:ancestor_reference_name, :modules_path, :module_type)

    ancestor_reference_name = options.fetch(:ancestor_reference_name)
    modules_path = options.fetch(:modules_path)
    module_type = options.fetch(:module_type)

    loader = loader_for_modules_path(modules_path)
    loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

    expect(loaded).to eq(true), "#{ancestor_reference_name} failed to load from #{modules_path}"
  end

  def expect_to_load_module_ancestors(options={})
    options.assert_valid_keys(:ancestor_reference_names, :modules_path, :module_type)

    ancestor_references_names = options.fetch(:ancestor_reference_names)

    ancestor_references_names.each do |ancestor_reference_name|
      expect_to_load_module_ancestor(
          ancestor_reference_name: ancestor_reference_name,
          modules_path: options[:modules_path],
          module_type: options[:module_type]
      )
    end
  end

  # Loads module ancestors with `:module_type` and `:ancestor_reference_names` from `:module_path` and then creates
  # module instance with `:module_type` and `:reference_name`.
  #
  # @param options [Hash{Symbol => Array<String>,<String>}]
  # @option options [Array<String>] :ancestor_reference_names the reference names of the ancestor modules for the module
  #   to be created.  Only staged payloads have two ancestors; all other modules, including single payloads, have one
  #   ancestor.
  # @option options [String] :modules_path path to the `modules` directory from which to load
  #   `:ancestor_reference_names`.
  # @option options [String] :module_type the type of module
  # @return [Msf::Module]
  def load_and_create_module(options={})
    options.assert_valid_keys(:ancestor_reference_names, :modules_path, :module_type, :reference_name)

    ancestor_reference_names = options.fetch(:ancestor_reference_names)
    module_type = options.fetch(:module_type)
    reference_name = options.fetch(:reference_name)

    expect_to_load_module_ancestors(
        options.except(:reference_name)
    )

    module_set = module_set_for_type(module_type)

    module_instance = module_set.create(reference_name)
    expect(module_instance).not_to(
        be_nil,
        "Could not create #{module_type}/#{reference_name} after loading #{ancestor_reference_names.sort.to_sentence}"
    )

    module_instance
  end

  def module_set_for_type(module_type)
    framework.modules.module_set(module_type)
  end

  #
  # lets
  #

  let(:modules_path) {
    Rails.application.paths['modules'].expanded.first
  }
end