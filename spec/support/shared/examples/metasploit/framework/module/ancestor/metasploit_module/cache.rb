shared_examples_for 'Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache' do
  include_context 'database cleaner'

  let(:module_ancestor) do
    FactoryGirl.build(
        module_ancestor_factory
    )
  end

  let(:module_ancestor_factory) do
    # payload types that require handler_type to be present
    [:single_payload_mdm_module_ancestor, :stager_payload_mdm_module_ancestor].sample
  end

  it { should be_a Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache }

  context '#cacheable_metasploit_class' do
    subject(:cacheable_metasploit_class) do
      metasploit_module.cacheable_metasploit_class(metasploit_class)
    end

    let(:metasploit_class) do
      Class.new
    end

    it { should be_a Metasploit::Framework::Module::Class::MetasploitClass }
    it { should include Metasploit::Framework::Module::Instance::MetasploitInstance }
  end

  context '#cache_handler_type' do
    subject(:cache_handler_type) do
      metasploit_module.cache_handler_type(module_ancestor)
    end

    context 'with #handler_type_alias' do
      let(:handler_type) do
        FactoryGirl.generate :metasploit_model_module_handler_type
      end

      before(:each) do
        handler_type = self.handler_type

        metasploit_module.define_singleton_method(:handler_type_alias) do
          handler_type
        end
      end

      it 'should set module_ancestor.handler_type' do
        expect {
          cache_handler_type
        }.to change(module_ancestor, :handler_type).to(metasploit_module.handler_type_alias)
      end
    end

    context 'without #handler_type_alias' do
      it 'should not raise error' do
        expect {
          cache_handler_type
        }.to_not raise_error
      end
    end
  end

  context '#cache_module_ancestor' do
    subject(:cache_module_ancestor) do
      metasploit_module.cache_module_ancestor(module_ancestor)
    end

    it 'should call cache_handler_type' do
      metasploit_module.should_receive(:cache_handler_type).with(module_ancestor)

      cache_module_ancestor
    end

    it 'should save inside of ActiveRecord::Base.connection_pool.with_connection' do
      module_ancestor.should_receive(:save) do
        backtrace = caller

        block_index = backtrace.index { |line|
          line.include? 'block in cache_module_ancestor'
        }

        # call to with_connection should outer farther back in backtrace
        ancestor_trace = backtrace[block_index + 1 .. - 1]
        ancestor_trace.find { |line|
          line.include? 'with_connection'
        }.should_not be_nil
      end

      cache_module_ancestor
    end
  end
end
