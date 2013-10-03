shared_examples_for 'Metasploit::Framework::Module::Cache#metasploit_class load non-payload' do |options={}|
  options.assert_valid_keys(:module_type)

  # don't call it module_type to prevent aliasing let
  context_module_type = options.fetch(:module_type)

  context "with #{context_module_type}" do
    let(:module_type) do
      context_module_type
    end

    context 'payload_type' do
      context 'with nil' do
        let(:payload_type) do
          nil
        end

        it_should_behave_like 'Metasploit::Framework::Module::Cache#metasploit_class load',
                              module_class_load_class: Metasploit::Framework::Module::Class::Load::NonPayload
      end

      context 'without nil' do
        let(:payload_type) do
          FactoryGirl.generate :metasploit_model_module_class_payload_type
        end

        it { should be_nil }
      end
    end
  end
end