# Loads, creates, and cleans up modules.
#
# @example Load and create encoder
#   include_context 'Msf::Simple::Framework#modules loading'
#
#   let(:encoder) {
#     load_and_create_module(
#       module_type: 'encoder',
#       reference_name: 'x86/shikata_ga_nai'
#     )
#   }
#
# @example Load and create staged payload
#   include_context 'Msf::Simple::Framework#modules loading'
#
#   let(:staged_payload) {
#     load_and_create_module(
#       ancestor_reference_names: %w{
#         stagers/android/reverse_https
#         stages/android/meterpreter
#       },
#       module_type: 'payload',
#       reference_name: 'android/meterpreter/reverse_tcp'
#     )
#   }
#
RSpec.shared_context 'Msf::Simple::Framework#modules loading' do
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Simple::Framework'

  #
  # Methods
  #

  # Derives ancestor reference names from `:reference_name`.
  #
  # @param options [Hash{Symbol => Array<String>,String}]
  # @option options [Array<String>] :ancestor_reference_names Override derivation from `:reference_name` and uses these
  #   `:ancestor_reference_names` instead.
  # @option options [String] :module_type the type of the module with `:reference_name`.
  # @option options [String] :reference_name the name of the module under `:module_type` whose ancestor reference names
  #   to derive.
  # @return [Array<String>] ancestor reference names.
  # @raise [KeyError] if `:ancestor_reference_names` is not given when `:module_type` is `'payload'`.
  # @raise [KeyError] unless `:module_type` is given.
  # @raise [KeyError] unless `:reference_name` is given.
  def derive_ancestor_reference_names(options={})
    options.assert_valid_keys(:ancestor_reference_names, :module_type, :reference_name)

    options.fetch(:ancestor_reference_names) {
      module_type = options.fetch(:module_type)

      if module_type == 'payload'
        raise KeyError, ":ancestor_reference_names must be given when :module_type is 'payload'"
      end

      # non-payload's single ancestor has the same reference name as the created module.
      reference_name = options.fetch(:reference_name)

      [reference_name]
    }
  end

  # The module loader that can load module ancestors from `modules_path`
  #
  # @param modules_path [String] path to `modules` directory from which to load ancestor reference names.
  # @return [Msf::Modules::Loader::Base]
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

  # Expects to load `:ancestor_reference_name` of `:module_type` from `:modules_path`.
  #
  # @raise expectation failure if `:ancestor_reference_name` cannot be loaded
  def expect_to_load_module_ancestor(options={})
    options.assert_valid_keys(:ancestor_reference_name, :modules_path, :module_type)

    ancestor_reference_name = options.fetch(:ancestor_reference_name)
    modules_path = options.fetch(:modules_path)
    module_type = options.fetch(:module_type)

    loader = loader_for_modules_path(modules_path)
    loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

    expect(loaded).to eq(true), "#{module_type}/#{ancestor_reference_name} failed to load from #{modules_path}"
  end

  # Expects to laod `:ancestor_reference_names` of `:module_type` from `:modules_path`
  #
  # @param options [Hash{Symbol => Array<String>, String}]
  # @option options [Array<String>] :ancestor_reference_names the reference names of the module ancestors of
  #   `:module_type` to load from `:modules_path`.
  # @option options [String] :modules_path The path from which to load `:ancestor_reference_names`.
  # @option options [Stirng] :module_type The type of `:ancestor_reference_names` to derive their full paths under
  #   `:modules_path`.
  # @raise expectation failure if any `:ancestor_reference_names` cannot be loaded.
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
  # @option options [String] :modules_path (#modules_path) the 'modules' directory from which to load
  #   `:ancestor_reference_names`.
  # @return [Msf::Module]
  # @raise [KeyError] if `:ancestor_reference_names` is not given when `:module_type` is `'payload'`.
  # @raise [KeyError] unless :module_type is given.
  # @raise [KeyError] unless :reference_name is given.
  def load_and_create_module(options={})
    options.assert_valid_keys(:ancestor_reference_names, :modules_path, :module_type, :reference_name)

    reference_name = options.fetch(:reference_name)
    module_type = options.fetch(:module_type)

    ancestor_reference_names = self.derive_ancestor_reference_names(
        options.except(:modules_path)
    )

    modules_path = options.fetch(:modules_path) {
      self.modules_path
    }

    expect_to_load_module_ancestors(
        ancestor_reference_names: ancestor_reference_names,
        modules_path: modules_path,
        module_type: module_type
    )

    module_set = module_set_for_type(module_type)

    module_instance = module_set.create(reference_name)
    expect(module_instance).not_to(
        be_nil,
        "Could not create #{module_type}/#{reference_name} after loading #{ancestor_reference_names.sort.to_sentence}"
    )

    module_instance
  end

  # The module set for `module_type`.
  #
  # @param module_type [String] the module type creatable by the module set.
  # @return [Msf::ModuleSet]
  def module_set_for_type(module_type)
    framework.modules.module_set(module_type)
  end

  #
  # lets
  #

  # The default modules path for this `Rails.application`.
  #
  # @return [String]
  let(:modules_path) {
    Rails.application.paths['modules'].expanded.first
  }
end