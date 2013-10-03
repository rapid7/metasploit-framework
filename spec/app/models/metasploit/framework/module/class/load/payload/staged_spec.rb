require 'spec_helper'

describe Metasploit::Framework::Module::Class::Load::Payload::Staged do
  include_context 'database seeds'

  subject(:module_class_load) do
    FactoryGirl.build(
        :metasploit_framework_module_class_load_payload_staged,
        module_class: module_class
    )
  end

  let(:module_class) do
    with_established_connection {
      FactoryGirl.create(
          :mdm_module_class,
          module_type: Metasploit::Model::Module::Type::PAYLOAD,
          payload_type: payload_type
      )
    }
  end

  let(:payload_type) do
    'staged'
  end

  it_should_behave_like 'Metasploit::Framework::Module::Class::Load::Payload::Base'

  context 'factories' do
    context 'metasploit_framework_module_class_load_payload_staged', pending: 'staged payload Class derivation' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      subject(:metasploit_framework_module_class_load_payload_staged) do
        with_established_connection {
          FactoryGirl.build(:metasploit_framework_module_class_load_payload_staged)
        }
      end

      it 'should be valid' do
        with_established_connection {
          metasploit_framework_module_class_load_payload_staged.should be_valid
        }
      end
    end
  end

  context 'validations' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    context 'payload_type' do
      subject(:payload_type_errors) do
        module_class_load.errors[:payload_type]
      end

      let(:error) do
        I18n.translate('errors.messages.inclusion')
      end

      before(:each) do
        with_established_connection do
          module_class_load.valid?
        end
      end

      context 'with single' do
        let(:payload_type) do
          'single'
        end

        it { should include(error) }
      end

      context 'with staged' do
        let(:payload_type) do
          'staged'
        end

        it { should_not include(error) }
      end
    end
  end

  context '#metasploit_class', pending: 'staged payload Class derivation' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    subject(:metasploit_class) do
      with_established_connection {
        module_class_load.metasploit_class
      }
    end

    it { should be_a Class }

    context 'ancestors' do
      subject(:ancestors) do
        metasploit_class.ancestors
      end

      it 'should have Class#ancestor with #module_ancestor for each Metasploit::Model::Module::Class#ancestors' do
        metasploit_modules = ancestors.select { |ancestor|
          ancestor.respond_to? :module_ancestor
        }

        metasploit_modules.should have(2).items

        actual_module_ancestors = metasploit_modules.map(&:module_ancestor)
        expected_module_ancestors = module_class.ancestors

        expect(actual_module_ancestors).to match_array(expected_module_ancestors)
      end
    end

    context 'module_class' do
      subject(:metasploit_class_module_class) do
        metasploit_class.module_class
      end

      it 'should match #module_class' do
        metasploit_class_module_class.should == module_class_load.module_class
      end
    end

    context 'with loaded' do
      before(:each) do
        with_established_connection do
          module_class_load.metasploit_class
        end
      end

      it 'should not reload ancestors' do
        Metasploit::Framework::Module::Ancestor::Load.should_not_receive(:new)

        module_class_load.metasploit_class
      end
    end

    context 'without loaded' do
      it 'should load the ancestors' do
        Metasploit::Framework::Module::Ancestor::Load.should_receive(:new).twice.and_call_original

        with_established_connection do
          module_class_load.metasploit_class
        end
      end
    end
  end

  context '#relative_constant_name' do
    subject(:relative_constant_name) do
      module_class_load.send(:relative_constant_name)
    end

    let(:stage_module_ancestor) do
      with_established_connection {
        module_class.ancestors.where(payload_type: 'stage').first
      }
    end

    let(:stage_partial_name) do
      described_class.module_ancestor_partial_name(stage_module_ancestor)
    end

    let(:stager_module_ancestor) do
      with_established_connection {
        module_class.ancestors.where(payload_type: 'stager').first
      }
    end

    let(:stager_partial_name) do
      described_class.module_ancestor_partial_name(stager_module_ancestor)
    end

    it 'should be partial name of both ancestors in fixed order' do
      relative_constant_name.should == "#{stage_partial_name}StagedBy#{stager_partial_name}"
    end
  end
end