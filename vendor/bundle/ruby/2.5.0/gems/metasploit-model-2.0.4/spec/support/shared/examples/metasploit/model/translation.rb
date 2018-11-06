RSpec.shared_examples_for 'Metasploit::Model::Translation' do |options={}|
  options.assert_valid_keys(:metasploit_model_ancestor)

  metasploit_model_ancestor = options.fetch(:metasploit_model_ancestor)

  it 'should include Metasploit::Model::Translation' do
    expect(base_class).to include Metasploit::Model::Translation
  end

  unless metasploit_model_ancestor.is_a? Class
    context metasploit_model_ancestor do
      context "dependencies" do
        subject(:dependencies) do
          metasploit_model_ancestor.instance_variable_get :@_dependencies
        end

        it { is_expected.to include Metasploit::Model::Translation }
      end
    end
  end

  context 'i18n_scope' do
    subject(:i18n_scope) do
      base_class.i18n_scope
    end

    it { is_expected.to eq('metasploit.model') }
  end

  context 'lookup_ancestors' do
    subject(:lookup_ancestors) do
      base_class.lookup_ancestors
    end

    it { is_expected.to include metasploit_model_ancestor }
  end
end