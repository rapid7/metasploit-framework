shared_examples_for 'payload can be instantiated' do |options|
  options.assert_valid_keys(:ancestor_reference_names, :modules_pathname, :reference_name)

  ancestor_reference_names = options.fetch(:ancestor_reference_names)

  modules_pathname = options.fetch(:modules_pathname)
  modules_path = modules_pathname.to_path

  reference_name = options.fetch(:reference_name)

  module_type = 'payload'

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

  let(:module_set) {
    framework.modules.module_set(module_type)
  }

  context reference_name  do
    ancestor_reference_names.each do |ancestor_reference_name|
      it "can load '#{module_type}/#{ancestor_reference_name}'" do
        @actual_ancestor_reference_name_set.add(ancestor_reference_name)

        loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

        expect(loaded).to eq(true), "#{ancestor_reference_name} failed to load from #{modules_path}"
      end
    end

    it 'can be instantiated' do
      ancestor_reference_names.each do |ancestor_reference_name|
        loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

        expect(loaded).to eq(true), "#{ancestor_reference_name} failed to load from #{modules_path}"
      end

      module_instance = nil

      expect {
        module_instance = module_set.create(reference_name)
      }.not_to raise_error

      expect(module_instance).not_to be_nil, "Could not instantiate #{module_type}/#{reference_name}"
    end
  end
end
