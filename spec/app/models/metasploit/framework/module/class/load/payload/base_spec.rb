require 'spec_helper'

describe Metasploit::Framework::Module::Class::Load::Payload::Base do
  include_context 'database cleaner'

  subject(:module_class_load) do
    FactoryGirl.build(
        :metasploit_framework_module_class_load_payload_base,
        module_class: module_class
    )
  end

  let(:module_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: Metasploit::Model::Module::Type::PAYLOAD
    )
  end

  context '#metasploit_class_from_child_constant' do
    subject(:metasploit_class_from_child_constant) do
      module_class_load.send(:metasploit_class_from_child_constant, metasploit_class)
    end

    let(:metasploit_class) do
      double('Metasploit Class')
    end

    it 'should pass through metasploit_class' do
      metasploit_class_from_child_constant.should == metasploit_class
    end
  end

  context 'parent_constant' do
    subject(:parent_constant) do
      described_class.parent_constant
    end

    it { should == Msf::Payloads }
  end

  context '#payload_type' do
    subject(:payload_type) do
      module_class_load.payload_type
    end

    context '#module_class' do
      context 'with nil' do
        let(:module_class) do
          nil
        end

        it { should be_nil }
      end

      context 'without nil' do
        it 'should delegate to Metasploit::Model::Module::Class#payload_type' do
          payload_type.should == module_class.payload_type
        end
      end
    end
  end
end