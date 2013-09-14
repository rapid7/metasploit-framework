require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy do
  subject(:validation_proxy) do
    described_class.new(target: target)
  end

  let(:target) do
    Module.new do
      class << self
        attr_accessor :metasploit_module
        attr_accessor :minimum_api_version
        attr_accessor :minimum_core_version
        attr_accessor :module_ancestor_eval_exception
      end
    end
  end

  it { should be_a Metasploit::Framework::ValidationProxy }

  context 'validations' do
    context 'metasploit_module' do
      it { should validate_presence_of :metasploit_module }

      context 'recursion' do
        let(:error) do
          I18n.translate('errors.messages.invalid')
        end

        before(:each) do
          target.metasploit_module = double('Metasploit Module', :valid? => valid?)

          validation_proxy.valid?
        end

        context 'with valid' do
          let(:valid?) do
            true
          end

          it 'should not record error on metasploit_module' do
            validation_proxy.errors[:metasploit_module].should_not include(error)
          end
        end

        context 'without valid' do
          let(:valid?) do
            false
          end

          it 'should record error on metasploit_module' do
            validation_proxy.errors[:metasploit_module].should include(error)
          end
        end
      end
    end

    it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy#minimum_*_version',
                          'API'
    it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy#minimum_*_version',
                          'Core'

    context 'module_ancestor_eval_exception' do
      it { should allow_value(nil).for(:module_ancestor_eval_exception) }

      it 'should not allow a non-nil value' do
        validation_proxy.should_not allow_value(Exception.new).for(:module_ancestor_eval_exception)
      end
    end
  end

  context 'model_name' do
    subject(:module_name) do
      described_class.model_name
    end

    it { should be_an ActiveModel::Name }

    its(:i18n_key) { should == :'metasploit/framework/module/ancestor/namespace' }
  end
end