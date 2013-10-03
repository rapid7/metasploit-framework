shared_examples_for 'Metasploit::Framework::Module::Cache#metasploit_class load' do |options={}|
  options.assert_valid_keys(:module_class_load_class)

  module_class_load_class = options.fetch(:module_class_load_class)

  it "should create a #{module_class_load_class}" do
    module_class_load_class.should_receive(:new).with(
        hash_including(
            cache: module_cache,
            module_class: module_class
        )
    ).and_call_original

    metasploit_class
  end

  context 'module class load validation' do
    before(:each) do
      module_class_load_class.any_instance.stub(valid?: valid)
    end

    context 'with valid' do
      let(:valid) do
        true
      end

      it 'should return Metasploit::Framework::Module::Class::Load::Base#metasploit_class' do
        expected_metasploit_class = double('metasploit_class')
        Metasploit::Framework::Module::Class::Load::Base.any_instance.stub(
            metasploit_class: expected_metasploit_class
        )

        metasploit_class.should == expected_metasploit_class
      end
    end

    context 'without valid' do
      let(:valid) do
        false
      end

      it { should be_nil }
    end
  end
end