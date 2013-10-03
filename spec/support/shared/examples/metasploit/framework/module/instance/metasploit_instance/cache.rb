shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache' do
  context '#cache_module_instance' do
    subject(:cache_module_instance) do
      base_instance.cache_module_instance(module_instance)
    end

    let(:module_class) do
      with_established_connection {
        FactoryGirl.create(:mdm_module_class)
      }
    end

    let(:module_instance) do
      with_established_connection {
        module_class.build_module_instance
      }
    end

    pending 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance implementation' do
      it 'should create Mdm::Module::Instance' do
        expect {
          cache_module_instance
        }.to change {
          with_established_connection {
            Mdm::Module::Instance.count
          }
        }.by(1)
      end

      it 'should populate Mdm::Module::Instance associations'
    end
  end
end