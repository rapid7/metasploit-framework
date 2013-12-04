require 'spec_helper'

describe Metasploit::Framework::Module::Class::Load::NonPayload do
  include_context 'database cleaner'

  subject(:module_class_load) do
    FactoryGirl.build(
        :metasploit_framework_module_class_load_non_payload,
        module_class: module_class
    )
  end

  let(:module_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: module_type
    )
  end

  let(:module_type) do
    FactoryGirl.generate :metasploit_model_non_payload_module_type
  end


  it_should_behave_like 'Metasploit::Framework::Module::Class::Load::Base'

  context 'factories' do
    context  'metasploit_framework_module_class_load_non_payload' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      subject(:metasploit_framework_module_class_load_non_payload) do
        FactoryGirl.build(:metasploit_framework_module_class_load_non_payload)
      end

      it 'should be valid' do
        metasploit_framework_module_class_load_non_payload.should be_valid
      end
    end
  end

  context 'validations' do
    context 'module_type' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      subject(:module_type_errors) do
        module_class_load.errors[:module_type]
      end

      let(:error) do
        I18n.translate('errors.messages.inclusion')
      end

      before(:each) do
        module_class_load.valid?
      end

      context 'with auxiliary' do
        let(:module_type) do
          'auxiliary'
        end

        it { should_not include(error) }
      end

      context 'with encoder' do
        let(:module_type) do
          'encoder'
        end

        it { should_not include(error) }
      end

      context 'with exploit' do
        let(:module_type) do
          'exploit'
        end

        it { should_not include(error) }
      end

      context 'with nop' do
        let(:module_type) do
          'nop'
        end

        it { should_not include(error) }
      end

      context 'with payload' do
        let(:module_type) do
          'payload'
        end

        it { should include(error) }
      end

      context 'with post' do
        let(:module_type) do
          'post'
        end

        it { should_not include(error) }
      end
    end
  end

  context '#metasploit_class' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    subject(:metasploit_class) do
      module_class_load.metasploit_class
    end

    it { should be_a Class }

    context 'module_ancestor' do
      subject(:metasploit_class_module_ancestor) do
        metasploit_class.module_ancestor
      end

      it "should match #module_class's only Metasploit::Model::Module::Class#ancestor" do
        metasploit_class_module_ancestor.should == module_class_load.module_class.ancestors.first
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

    context 'name' do
      subject(:name) do
        metasploit_class.name
      end

      let(:module_ancestor) do
        module_class.ancestors.first
      end

      let(:real_path_sha1_hex_digest) do
        module_ancestor.real_path_sha1_hex_digest
      end

      it 'should contain Metasploit::Model::Module::Ancestor#real_path_sha1_hex_digest' do
        name.should include(real_path_sha1_hex_digest)
      end
    end

    context 'with loaded' do
      before(:each) do
        module_class_load.metasploit_class
      end

      it 'should not reload the ancestors' do
        Metasploit::Framework::Module::Ancestor::Load.should_not_receive(:new)

        module_class_load.metasploit_class
      end
    end

    context 'without loaded' do
      it 'should load the ancestors' do
        Metasploit::Framework::Module::Ancestor::Load.should_receive(:new).and_call_original

        module_class_load.metasploit_class
      end
    end
  end

  context '#metasploit_class_from_child_constant' do
    subject(:metasploit_class_from_child_constant) do
      module_class_load.send(:metasploit_class_from_child_constant, child_constant)
    end

    let(:child_constant) do
      Module.new {}
    end

    it 'should retrieve metasploit_module from namespace_module' do
      metasploit_module = double('metasploit_module').as_null_object
      child_constant.should_receive(:metasploit_module).and_return(metasploit_module)


      metasploit_class_from_child_constant
    end

    it 'should take first class from metasploit_module because it only has one class' do
      metasploit_module = double('metasploit_module')
      child_constant.stub(metasploit_module: metasploit_module)

      metasploit_class = double('metasploit_class')

      metasploit_class_enumerator = double('metasploit_class Enumerator')
      metasploit_class_enumerator.should_receive(:first).and_return(metasploit_class)

      metasploit_module.should_receive(:each_metasploit_class).and_return(metasploit_class_enumerator)

      metasploit_class_from_child_constant.should == metasploit_class
    end
  end

  context 'parent_constant' do
    subject(:parent_constant) do
      described_class.parent_constant
    end

    it { should == Msf::Modules }
  end

  context '#relative_constant_name' do
    subject(:relative_constant_name) do
      module_class_load.send(:relative_constant_name)
    end

    it 'should be partial name of the only module ancestor' do
      relative_constant_name.should == described_class.module_ancestor_partial_name(module_class.ancestors.first)
    end
  end
end