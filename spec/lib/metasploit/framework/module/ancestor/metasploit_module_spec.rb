require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::MetasploitModule do
  subject(:metasploit_module) do
    described_class = self.described_class

    Module.new do
      extend described_class
    end
  end

  it_should_behave_like 'Metasploit::Framework::ProxiedValidation' do
    let(:target) do
      metasploit_module
    end
  end

  context 'validations' do
    context 'usable' do
      context 'default' do
        it { should be_valid }
      end

      context 'with is_usable false' do
        let(:error) do
          I18n.translate('activemodel.errors.models.metasploit/framework/module/ancestor/metasploit_module.attributes.base.unusable')
        end

        before(:each) do
          metasploit_module.module_eval do
            def self.is_usable
              false
            end
          end
        end

        it { should_not be_valid }

        it 'should add error on :base' do
          metasploit_module.valid?

          metasploit_module.errors[:base].should include(error)
        end
      end
    end
  end

  context '#is_usable' do
    subject(:is_usable) do
      metasploit_module.is_usable
    end

    it { should be_true }
  end

  context '#validation_proxy_class' do
    subject(:validation_proxy_class) do
      metasploit_module.validation_proxy_class
    end

    it { should == Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy }
  end
end