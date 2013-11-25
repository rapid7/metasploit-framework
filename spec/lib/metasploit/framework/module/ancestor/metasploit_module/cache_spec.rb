require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache do
  subject(:base_module) do
    described_class = self.described_class

    Module.new do
      extend described_class
    end
  end

  context '#cache_module_ancestor' do
    include_context 'database seeds'

    #
    # lets
    #

    let(:module_ancestor) do
      FactoryGirl.build(
          :mdm_module_ancestor
      )
    end

    #
    # callbacks
    #

    around(:each) do |example|
      with_established_connection do
        example.run
      end
    end

    before(:each) do
      if module_ancestor.handled?
        base_module.stub(handler_type_alias: "stubbed_handler_type_alias")
      end
    end

    context 'with module_ancestor' do
      subject(:cache_module_ancestor) do
        base_module.cache_module_ancestor(module_ancestor)
      end

      it 'should batch save module_ancestor' do
        module_ancestor.should_receive(:batched_save)

        cache_module_ancestor
      end

      it 'should cache Module::Ancestor' do
        expect {
          cache_module_ancestor
        }.to change(Mdm::Module::Ancestor, :count).by(1)
      end

      context 'without saved' do
        before(:each) do
          module_ancestor.should_receive(:batched_save).and_return(false)
        end

        it 'should log error' do
          base_module.should_receive(:elog)

          cache_module_ancestor
        end
      end
    end

    context 'without module_ancestor' do
      subject(:cache_module_ancestor) do
        base_module.cache_module_ancestor
      end

      it 'should call #module_ancestor' do
        base_module.should_receive(:module_ancestor).and_return(module_ancestor)

        cache_module_ancestor
      end
    end
  end
end