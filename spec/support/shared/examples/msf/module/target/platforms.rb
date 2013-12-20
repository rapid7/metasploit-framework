shared_examples_for 'Msf::Module::Target::Platforms' do
  context '#declared_platform_list' do
    subject(:declared_platform_list) do
      target.declared_platform_list
    end

    context "with 'Platforms'" do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:metasploit_instance) do
        double('#metasploit_instance')
      end

      let(:module_class) do
        FactoryGirl.create(:mdm_module_class)
      end

      let(:module_class_full_name) do
        module_class.full_name
      end

      let(:options) do
        {
            'Platform' => platform_fully_qualified_names
        }
      end

      let(:platforms) do
        Metasploit::Framework::Platform.all.sample(2)
      end

      let(:platform_fully_qualified_names) do
        platforms.map(&:fully_qualified_name)
      end

      #
      # Callbacks
      #

      before(:each) do
        klass = double(module_class: module_class)
        metasploit_instance.stub(class: klass)
        target.metasploit_instance = metasploit_instance
      end

      it 'should call Msf::Module::PlatformList.transform' do
        Msf::Module::PlatformList.should_receive(:transform).with(
            platform_fully_qualified_names,
            hash_including(
                module_class_full_names: [
                    module_class_full_name
                ]
            )
        )

        declared_platform_list
      end
    end

    context "without 'Platforms'" do
      it { should be_nil }
    end
  end
end