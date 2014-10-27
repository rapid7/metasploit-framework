shared_examples_for 'all modules with module type can be instantiated' do |options={}|
  options.assert_valid_keys(:module_type, :modules_pathname, :type_directory)

  module_type = options.fetch(:module_type)
  modules_pathname = options.fetch(:modules_pathname)
  modules_path = modules_pathname.to_path
  type_directory = options.fetch(:type_directory)

  include_context 'Msf::Simple::Framework'

  #
  # lets
  #

  let(:loader) {
    loader = framework.modules.send(:loaders).find { |loader|
      loader.loadable?(modules_path)
    }

    # Override load_error so that rspec will print it instead of going to framework log
    def loader.load_error(module_path, error)
      raise error
    end

    loader
  }

  context module_type do
    let(:module_set) {
      framework.modules.module_set(module_type)
    }

    type_pathname = modules_pathname.join(type_directory)
    module_extension = ".rb"
    module_extension_regexp = /#{Regexp.escape(module_extension)}$/

    Dir.glob(type_pathname.join('**', "*#{module_extension}")) do |module_path|
      module_pathname = Pathname.new(module_path)
      module_reference_pathname = module_pathname.relative_path_from(type_pathname)
      module_reference_name = module_reference_pathname.to_path.gsub(module_extension_regexp, '')

      context module_reference_name do
        it 'can be instantiated' do
          loaded = loader.load_module(modules_path, module_type, module_reference_name)

          expect(loaded).to eq(true), "#{module_reference_name} failed to load from #{modules_path}"

          module_instance = nil

          expect {
            module_instance = module_set.create(module_reference_name)
          }.not_to raise_error

          expect(module_instance).not_to be_nil, "Could not instantiate #{module_type}/#{module_reference_name}"
        end
      end
    end
  end
end
