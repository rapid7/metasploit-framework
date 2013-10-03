require 'spec_helper'

require 'weakref'

describe Metasploit::Framework::Module::Ancestor::MetasploitModule do
  include_context 'database seeds'

  subject(:metasploit_module) do
    described_class = self.described_class
    rank = self.rank

    Module.new {
      extend described_class
    }.tap { |m|
      m.define_singleton_method(:rank_name) do
        rank.name
      end
    }
  end

  let(:module_class) do
    with_established_connection do
      FactoryGirl.build(
          :mdm_module_class,
          # nil rank as #cache is expected to set rank
          rank: nil
      )
    end
  end

  let(:rank) do
    with_established_connection {
      FactoryGirl.generate :mdm_module_rank
    }
  end

  it_should_behave_like 'Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache'

  it_should_behave_like 'Metasploit::Framework::ProxiedValidation' do
    let(:target) do
      metasploit_module
    end
  end

  context 'resurrecting attributes' do
    context '#module_ancestor' do
      subject(:module_ancestor) do
        with_established_connection {
          metasploit_module.module_ancestor
        }
      end

      let(:expected_module_ancestor) do
        with_established_connection {
          FactoryGirl.create(:mdm_module_ancestor)
        }
      end

      before(:each) do
        # have to stub because real_path_sha1_hex_digest is normally delegated to the namespace parent
        metasploit_module.stub(real_path_sha1_hex_digest: expected_module_ancestor.real_path_sha1_hex_digest)
      end

      it 'should be Mdm::Module::Ancestor with matching #real_path_sha1_hex_digest' do
        module_ancestor.should == expected_module_ancestor
      end
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

  context '#each_metasploit_classes' do
    include_context 'database cleaner'
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    # no subject() since we need to take a block and don't want to have a fixed block in context
    def each_metasploit_class(&block)
      metasploit_module.each_metasploit_class(&block)
    end

    let(:metasploit_module) do
      with_established_connection {
        module_ancestor_load.metasploit_module
      }
    end

    let(:module_ancestor_load) do
      Metasploit::Framework::Module::Ancestor::Load.new(
          module_ancestor: module_ancestor
      )
    end

    context '#module_type' do
      let(:module_ancestor) do
        with_established_connection {
          FactoryGirl.create(
              :mdm_module_ancestor,
              module_type: module_type,
              payload_type: payload_type
          )
        }
      end

      context 'with payload' do
        let(:module_type) do
          Metasploit::Model::Module::Type::PAYLOAD
        end

        context 'payload_type' do
          context 'with single' do
            let(:payload_type) do
              'single'
            end

            it 'should contain only one Class' do
              count = 0

              each_metasploit_class do |metasploit_class|
                metasploit_class.should be_a Class
                count += 1
              end

              count.should == 1
            end

            context 'metasploit_class' do
              subject(:metasploit_class) do
                each_metasploit_class.first
              end

              it 'should be a subclass of Msf::Payload' do
                expect(metasploit_class).to be < Msf::Payload
              end

              it 'should include this metasploit module' do
                metasploit_class.should include(metasploit_module)
              end

              it 'should include handler_module' do
                metasploit_class.should include(metasploit_module.handler_module)
              end
            end
          end

          context 'with stage' do
            let(:payload_type) do
              'stage'
            end

            it 'should contain at least one Class' do
              count = 0

              each_metasploit_class do |metasploit_class|
                metasploit_class.should be_a Class
                count += 1
              end

              pending 'Metasploit::Framework::Module::Ancestor::MetasploitModule#each_module_class for stage payloads' do
                count.should be > 1
              end
            end

            context 'metasploit_classes' do
              subject(:metasploit_classes) do
                each_metasploit_class
              end

              it 'should be subclasses of Msf::Payload' do
                each_metasploit_class do |metasploit_class|
                  expect(metasploit_class).to be < Msf::Payload
                end
              end

              it 'should include this metasploit module' do
                each_metasploit_class do |metasploit_class|
                  metasploit_class.should include(metasploit_module)
                end
              end

              it 'should include handler_module from stager'

              it 'should include metasploit module from stager'
            end
          end

          context 'with stager' do
            let(:payload_type) do
              'stager'
            end

            it 'should contain at least one Class' do
              count = 0

              each_metasploit_class do |metasploit_class|
                metasploit_class.should be_a Class
                count += 1
              end

              pending 'Metasploit::Framework::Module::Ancestor::MetasploitModule#each_module_class for stager payloads' do
                count.should be > 1
              end
            end

            context 'metasploit_classes' do
              subject(:metasploit_classes) do
                each_metasploit_class
              end

              it 'should be subclasses of Msf::Payload' do
                each_metasploit_class do |metasploit_class|
                  expect(metasploit_class).to be < Msf::Payload
                end
              end

              it 'should include this metasploit module' do
                each_metasploit_class do |metasploit_class|
                  metasploit_class.should include(metasploit_module)
                end
              end

              it 'should include handler_module' do
                each_metasploit_class do |metasploit_class|
                  metasploit_class.should include(metasploit_module.handler_module)
                end
              end

              it 'should include metasploit module from stage'
            end
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

        it 'should contain only the metasploit_module itself because it is a Class already' do
          expect(each_metasploit_class.to_a).to match_array([metasploit_module])
        end

        context 'metasploit_class' do
          subject(:metasploit_class) do
            each_metasploit_class.first
          end

          it { should be_a Metasploit::Framework::Module::Class::MetasploitClass }
          it { should include(Metasploit::Framework::Module::Instance::MetasploitInstance) }
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

  context '#module_type' do
    subject(:module_type) do
      metasploit_module.module_type
    end

    let(:parent) do
      double('Namespace Module', module_type: expected_module_type)
    end

    let(:expected_module_type) do
      FactoryGirl.generate :metasploit_model_module_type
    end

    before(:each) do
      metasploit_module.stub(parent: parent)
    end

    it 'should delegate to #parent' do
      module_type.should == parent.module_type
    end
  end

  context '#payload_type' do
    subject(:payload_type) do
      metasploit_module.payload_type
    end

    let(:parent) do
      double('Namespace Module', payload_type: expected_payload_type)
    end

    let(:expected_payload_type) do
      FactoryGirl.generate :metasploit_model_module_ancestor_payload_type
    end

    before(:each) do
      metasploit_module.stub(parent: parent)
    end

    it 'should delegate to #parent' do
      payload_type.should == parent.payload_type
    end
  end

  context '#real_path_sha1_hex_digest' do
    subject(:real_path_sha1_hex_digest) do
      metasploit_module.real_path_sha1_hex_digest
    end

    let(:parent) do
      double('Namespace Module', real_path_sha1_hex_digest: expected_real_path_sha1_hex_digest)
    end

    let(:expected_real_path_sha1_hex_digest) do
      Digest::SHA1.new.tap { |d| d << 'parent' }.hexdigest
    end

    before(:each) do
      metasploit_module.stub(parent: parent)
    end

    it 'should delegate to #parent' do
      real_path_sha1_hex_digest.should == parent.real_path_sha1_hex_digest
    end
  end

  context '#validation_proxy_class' do
    subject(:validation_proxy_class) do
      metasploit_module.validation_proxy_class
    end

    it { should == Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy }
  end
end