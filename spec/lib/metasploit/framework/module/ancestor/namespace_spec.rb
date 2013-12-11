# -*- coding:binary -*-
require 'spec_helper'

describe Metasploit::Framework::Module::Ancestor::Namespace do
  subject(:namespace) do
    Module.new.tap do |namespace|
      namespace.module_eval Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_CONTENT,
                            Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_FILE,
                            Metasploit::Framework::Module::Ancestor::Load::NAMESPACE_MODULE_LINE
    end
  end

  # @return (see Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval)
  def module_ancestor_eval_with_namespace_attributes
    namespace.module_type = module_ancestor.module_type
    namespace.payload_type = module_ancestor.payload_type
    namespace.real_path_sha1_hex_digest = module_ancestor.real_path_sha1_hex_digest

    namespace.module_ancestor_eval(module_ancestor)
  end

  it 'should extend Metasploit::Framework::Module::Ancestor::Namespace' do
    namespace.singleton_class.include? described_class
  end

  it_should_behave_like 'Metasploit::Framework::ProxiedValidation' do
    let(:target) do
      namespace
    end
  end

  context '#metasploit_module' do
    before(:each) do
      if major
        subject.const_set("Metasploit#{major}", Class.new)
      end
    end

    context 'without Metasploit<n> constant defined' do
      let(:major) do
        nil
      end

      it 'should not be defined' do
        metasploit_constants = subject.constants.select { |constant|
          constant.to_s =~ /Metasploit/
        }

        metasploit_constants.should be_empty
      end
    end

    context 'with Metasploit1 constant defined' do
      let(:major) do
        1
      end

      it 'should be defined' do
        subject.const_defined?('Metasploit1').should be_true
      end

      it 'should return the class' do
        subject.metasploit_module.should be_a Class
      end
    end

    context 'with Metasploit2 constant defined' do
      let(:major) do
        2
      end

      it 'should be defined' do
        subject.const_defined?('Metasploit2').should be_true
      end

      it 'should return the class' do
        subject.metasploit_module.should be_a Class
      end
    end

    context 'with Metasploit3 constant defined' do
      let(:major) do
        3
      end

      it 'should be defined' do
        subject.const_defined?('Metasploit3').should be_true
      end

      it 'should return the class' do
        subject.metasploit_module.should be_a Class
      end
    end

    context 'with Metasploit4 constant defined' do
      let(:major) do
        4
      end

      it 'should be defined' do
        subject.const_defined?('Metasploit4').should be_true
      end

      it 'should return the class' do
        subject.metasploit_module.should be_a Class
      end
    end

    context 'with Metasploit5 constant defined' do
      let(:major) do
        5
      end

      it 'should be defined' do
        subject.const_defined?('Metasploit5').should be_true
      end

      it 'should be newer than Msf::Framework::Major' do
        major.should > Msf::Framework::Major
      end

      it 'should return nil' do
        subject.metasploit_module.should be_nil
      end
    end
  end

  context '#minimum_api_version' do
    subject(:minimum_api_version) do
      namespace.minimum_api_version
    end

    let(:required_versions) do
      [4, 2]
    end

    before(:each) do
      namespace.stub(required_versions: required_versions)
    end

    it 'should be second element of #required_versions' do
      minimum_api_version.should == required_versions.second
    end
  end

  context '#minimum_core_version' do
    subject(:minimum_core_version) do
      namespace.minimum_core_version
    end

    let(:required_versions) do
      [4, 2]
    end

    before(:each) do
      namespace.stub(required_versions: required_versions)
    end

    it 'should be first element of #required_versions' do
      minimum_core_version.should == required_versions.first
    end
  end

  context '#module_ancestor_eval' do
    include_context 'database cleaner'

    subject(:module_ancestor_eval) do
      module_ancestor_eval_with_namespace_attributes
    end

    let(:module_ancestor) do
      FactoryGirl.create(:mdm_module_ancestor)
    end

    context 'with Interrupt' do
      before(:each) do
        namespace.stub(:module_eval_with_lexical_scope).and_raise(Interrupt)
      end

      it 'should raise Interrupt' do
        expect {
          module_ancestor_eval
        }.to raise_error(Interrupt)
      end
    end

    context 'with Exception' do
      let(:exception_class) do
        Exception
      end

      let(:exception_message) do
        'exception from module_ancestor.contents'
      end

      before(:each) do
        File.open(module_ancestor.real_path, 'wb') do |f|
          f.puts "raise #{exception_class}, #{exception_message.inspect}"
        end
      end

      it 'should not raise Exception' do
        expect {
          module_ancestor_eval
        }.to_not raise_error
      end

      it 'should set #module_ancestor_eval_exception to raised Exception' do
        module_ancestor_eval

        namespace.module_ancestor_eval_exception.should be_an exception_class
        namespace.module_ancestor_eval_exception.message.should == exception_message
      end

      it 'should make namespace invalid due to #module_ancestor_eval_exception' do
        namespace.should be_invalid
      end

      it { should be_false }
    end

    context 'without Exception' do
      it 'should call #valid?' do
        namespace.should_receive(:valid?).and_return(false)

        module_ancestor_eval
      end

      context 'with valid' do
        context 'Metasploit::Model::Module::Ancestor#module_type' do
          let(:module_ancestor) do
            # only build so that handler_type has to be set by module_ancestor_eval for Mdm::Module::Ancestor to save!
            FactoryGirl.build(
                :mdm_module_ancestor,
                module_type: module_type,
                payload_type: payload_type
            )
          end

          before(:each) do
            module_ancestor.valid?(:loading)

            # preserve original handler_type for checking call to metasploit_module.handler_type_alias
            # factory needs to pick handler_type so contents written to disk have self.handler_type_alias method.
            @original_handler_type = module_ancestor.handler_type
            # nil handler_type has to be set by module_ancestor_eval for Mdm::Module::Ancestor to save!
            module_ancestor.handler_type = nil
          end

          context 'with payload' do
            let(:module_type) do
              Metasploit::Model::Module::Type::PAYLOAD
            end

            context 'Metasploit::Model::Module::Ancestor#payload_type' do
              context 'with single' do
                let(:payload_type) do
                  'single'
                end

                it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval with Metasploit::Module::Module::Ancestor#handled?'
              end

              context 'with stage' do
                let(:payload_type) do
                  'stage'
                end

                it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval true'
              end

              context 'with stager' do
                let(:payload_type) do
                  'stager'
                end

                it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval with Metasploit::Module::Module::Ancestor#handled?'
              end
            end
          end

          context 'without payload' do
            let(:module_type) do
              FactoryGirl.generate :metasploit_model_non_payload_module_type
            end

            let(:payload_type) do
              nil
            end

            it_should_behave_like 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval true'
          end
        end
      end

      context 'without valid' do
        before(:each) do
          namespace.stub(valid?: false)
        end

        it { should be_false }
      end
    end
  end

  context '#module_type' do
    subject(:module_type) do
      namespace.module_type
    end

    let(:expected_module_type) do
      FactoryGirl.generate :metasploit_model_module_type
    end

    it 'should be accessor' do
      namespace.module_type = expected_module_type
      module_type.should == expected_module_type
    end
  end

  context '#payload?' do
    subject(:payload?) do
      namespace.payload?
    end

    context '#module_type' do
      before(:each) do
        namespace.module_type = module_type
      end

      context 'with payload' do
        let(:module_type) do
          'payload'
        end

        it { should be_true }
      end

      context 'without payload' do
        let(:module_type) do
          FactoryGirl.generate :metasploit_model_non_payload_module_type
        end

        it { should be_false }
      end
    end
  end

  context '#payload_type' do
    subject(:payload_type) do
      namespace.payload_type
    end

    let(:expected_payload_type) do
      FactoryGirl.generate :metasploit_model_module_ancestor_payload_type
    end

    it 'should be accessor' do
      namespace.payload_type = expected_payload_type
      payload_type.should == expected_payload_type
    end
  end

  context '#real_path_sha1_hex_digest' do
    subject(:real_path_sha1_hex_digest) do
      namespace.real_path_sha1_hex_digest
    end

    let(:expected_real_path_sha1_hex_digest) do
      Digest::SHA1.hexdigest('expected')
    end

    it 'should be accessor' do
      namespace.real_path_sha1_hex_digest = expected_real_path_sha1_hex_digest
      real_path_sha1_hex_digest.should == expected_real_path_sha1_hex_digest
    end
  end

  context '#required_versions' do
    include_context 'database cleaner'

    subject(:required_versions) do
      namespace.required_versions
    end

    #
    # lets
    #

    let(:module_ancestor) do
      FactoryGirl.build(:mdm_module_ancestor)
    end

    #
    # callbacks
    #

    before(:each) do
      module_ancestor.valid?(:loading).should be_true
    end

    context 'with RequiredVersions' do
      let(:minimum_api_version) do
        1
      end

      let(:minimum_core_version) do
        2
      end

      before(:each) do
        real_path = module_ancestor.real_path
        backup_real_path = "#{real_path}.bak"
        FileUtils.copy_file(real_path, backup_real_path)

        File.open(module_ancestor.real_path, 'wb') do |f|
          f.puts "RequiredVersions = [#{minimum_core_version}, #{minimum_api_version}]"
          f.puts ""

          File.foreach(backup_real_path) do |line|
            f.puts line
          end
        end

        File.delete(backup_real_path)

        module_ancestor_eval_with_namespace_attributes.should be_true
      end

      it 'should be RequiredVersions constant in namespace' do
        required_versions.should == [minimum_core_version, minimum_api_version]
      end
    end

    context 'without RequiredVersions' do
      before(:each) do
        module_ancestor_eval_with_namespace_attributes.should be_true
      end

      it { should == [nil, nil] }
    end
  end
end
