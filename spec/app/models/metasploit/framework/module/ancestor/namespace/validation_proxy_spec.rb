require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy do
  subject(:validation_proxy) do
    described_class.new(target: target)
  end

  let(:target) do
    Module.new do
      class << self
        #
        # Attributes
        #

        attr_accessor :metasploit_module
        attr_accessor :minimum_api_version
        attr_accessor :minimum_core_version
        attr_accessor :module_ancestor_eval_exception
        attr_accessor :module_type
        attr_accessor :payload_type
        attr_accessor :real_path_sha1_hex_digest

        #
        # Methods
        #

        def payload?
          module_type == Metasploit::Model::Module::Type::PAYLOAD
        end
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

    it { should ensure_inclusion_of(:module_type).in_array(Metasploit::Model::Module::Type::ALL) }

    context 'payload_type' do
      context '#module_type' do
        before(:each) do
          target.module_type = module_type
        end

        context 'with payload' do
          let(:module_type) do
            Metasploit::Model::Module::Type::PAYLOAD
          end

          it { should ensure_inclusion_of(:payload_type).in_array(Metasploit::Model::Module::Ancestor::PAYLOAD_TYPES) }
        end

        context 'without payload' do
          let(:module_type) do
            FactoryGirl.generate :metasploit_model_non_payload_module_type
          end

          before(:each) do
            target.payload_type = payload_type
          end

          context 'with nil' do
            let(:payload_type) do
              nil
            end

            it 'should not add error on :payload_type' do
              validation_proxy.valid?

              validation_proxy.errors[:payload_type].should be_empty
            end
          end

          context 'without nil' do
            let(:error) do
              'must be nil'
            end

            let(:payload_type) do
              FactoryGirl.generate :metasploit_model_module_ancestor_payload_type
            end

            it 'should add error on :payload_type' do
              validation_proxy.valid?

              validation_proxy.errors[:payload_type].should include(error)
            end
          end
        end
      end
    end

    context 'validates format with Metasploit::Model::Module::Ancestor::SHA1_HEX_DIGEST_REGEXP' do
      let(:hexdigest) do
        Digest::SHA1.hexdigest('')
      end

      it 'should allow a Digest::SHA1.hexdigest' do
        validation_proxy.should allow_value(hexdigest).for(:real_path_sha1_hex_digest)
      end

      it 'should not allow a truncated Digest::SHA1.hexdigest' do
        validation_proxy.should_not allow_value(hexdigest[0, 39]).for(:real_path_sha1_hex_digest)
      end

      it 'should not allow upper case hex to maintain normalization' do
        validation_proxy.should_not allow_value(hexdigest.upcase).for(:real_path_sha1_hex_digest)
      end

      it { should_not allow_value(nil).for(:real_path_sha1_hex_digest) }
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