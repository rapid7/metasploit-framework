RSpec.describe Metasploit::Model::Translation do
  let(:base_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  context 'lookup_ancestors' do
    subject(:lookup_ancestors) do
      base_class.lookup_ancestors
    end

    let(:base_class) do
      described_class = self.described_class

      Class.new(named_class) do
        include described_class
      end
    end

    let(:named_class) do
      named_module = self.named_module
      unnamed_class = self.unnamed_class

      Class.new(unnamed_class) do
        include named_module

        def self.model_name

        end
      end
    end

    let(:named_module) do
      Module.new do
        def self.model_name

        end
      end
    end

    let(:unnamed_class) do
      unnamed_module = self.unnamed_module

      Class.new do
        include unnamed_module
      end
    end

    let(:unnamed_module) do
      Module.new
    end

    it 'should have named and unnamed ancestors' do
      expect(base_class.ancestors).to include(named_class)
      expect(base_class.ancestors).to include(named_module)
      expect(base_class.ancestors).to include(unnamed_class)
      expect(base_class.ancestors).to include(unnamed_module)
    end

    it 'should return all ancestors that respond to model_name' do
      expect(lookup_ancestors).to include(base_class)
      expect(lookup_ancestors).to include(named_class)
      expect(lookup_ancestors).to include(named_module)
    end

    it 'should not return ancestors that do not respond to model_name' do
      expect(lookup_ancestors).not_to include(unnamed_class)
      expect(lookup_ancestors).not_to include(unnamed_module)
    end
  end

  context 'i18n_scope' do
    subject(:i18n_scope) do
      'metasploit.model'
    end
  end
end