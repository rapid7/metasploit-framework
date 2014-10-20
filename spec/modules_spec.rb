require 'spec_helper'

describe 'modules' do
  include_context 'Msf::Simple::Framework'

  modules_pathname = Pathname.new(__FILE__).parent.parent.join('modules')
  modules_path = modules_pathname.to_path

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

  type = 'auxiliary'
  context type do
    let(:module_set) {
      framework.send(type)
    }

    type_pathname = modules_pathname.join('auxiliary')

    Dir.glob(type_pathname.join('**', '*.rb')) do |module_path|
      module_pathname = Pathname.new(module_path)
      module_reference_pathname = module_pathname.relative_path_from(type_pathname)
      module_reference_name = module_reference_pathname.to_path.gsub(/\.rb$/, '')

      context module_reference_name do
        it 'can be instantiated' do
          loaded = loader.load_module(modules_path, type, module_reference_name)

          expect(loaded).to eq(true), "#{module_reference_name} failed to load from #{modules_path}"

          module_instance = nil

          expect {
            module_instance = module_set.create(module_reference_name)
          }.not_to raise_error

          expect(module_instance).not_to be_nil, "Could not instantiate #{type}/#{module_reference_name}"
        end
      end
    end
  end
end