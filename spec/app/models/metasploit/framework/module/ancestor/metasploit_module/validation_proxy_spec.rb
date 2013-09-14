require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy do
  subject(:validation_proxy) do
    described_class.new(target: target)
  end

  let(:target) do
    Module.new do
      def is_usable
        true
      end
    end
  end

  it { should be_a Metasploit::Framework::ValidationProxy }

  context 'validation' do
    it 'should call #usable' do
      validation_proxy.should_receive(:usable)

      validation_proxy.valid?
    end
  end

  context 'model_name' do
    subject(:module_name) do
      described_class.model_name
    end

    it { should be_an ActiveModel::Name }

    its(:i18n_key) { should == :'metasploit/framework/module/ancestor/metasploit_module' }
  end

  context '#usable' do
    let(:error) do
      I18n.translate('unusable')
    end

    before(:each) do
      target.stub(is_usable: is_usable)
    end

    context 'with is_usable' do
      let(:is_usable) do
        true
      end

      it 'should not add error on base' do
        validation_proxy.errors[:base].should_not include(error)
      end
    end

    context 'without is_usable' do
      let(:is_usable) do
        false
      end

      it 'should add error on base' do
        validation_proxy.errors[:base].should_not include(error)
      end
    end
  end
end