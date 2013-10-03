shared_examples_for 'Metasploit::Framework::Module::Class::Load::Payload::Base' do
  it_should_behave_like 'Metasploit::Framework::Module::Class::Load::Base'

  context 'validations' do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    context 'module_type' do
      subject(:module_type_errors) do
        module_class_load.errors[:module_type]
      end

      let(:error) do
        I18n.translate('errors.messages.inclusion')
      end

      let(:module_class) do
        with_established_connection {
          FactoryGirl.create(
              :mdm_module_class,
              module_type: module_type
          )
        }
      end

      before(:each) do
        with_established_connection do
          module_class_load.valid?
        end
      end

      context 'with payload' do
        let(:module_type) do
          Metasploit::Model::Module::Type::PAYLOAD
        end

        it { should_not include(error) }
      end

      context 'without payload' do
        let(:module_type) do
          Metasploit::Model::Module::Type::NON_PAYLOAD.sample
        end

        it { should include(error) }
      end
    end
  end

  context '#class_from_child_constant' do
    subject(:class_from_child_constant) do
      module_class_load.send(:metasploit_class_from_child_constant, metasploit_class)
    end

    let(:metasploit_class) do
      double('Msf::Payload')
    end

    it 'should return the given value' do
      class_from_child_constant.should == metasploit_class
    end
  end

  context 'parent_constant' do
    subject(:parent_constant) do
      described_class.parent_constant
    end

    it { should == Msf::Payloads }
  end
end