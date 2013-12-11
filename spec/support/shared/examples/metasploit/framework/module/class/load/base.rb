shared_examples_for 'Metasploit::Framework::Module::Class::Load::Base' do
  context 'validations' do
    it { should validate_presence_of :cache }
    it { should validate_presence_of :module_class }

    context 'metasploit_class' do
      subject(:metasploit_class_errors) do
        module_class_load.errors[:metasploit_class]
      end

      let(:error) do
        I18n.translate('errors.messages.blank')
      end

      before(:each) do
        module_class_load.stub(metasploit_class: metasploit_class)
      end

      context 'with :loading' do
        before(:each) do
          module_class_load.valid?(:loading)
        end

        context 'without metasploit_class' do
          let(:metasploit_class) do
            nil
          end

          it { should_not include(error) }
        end
      end

      context 'without :loading' do
        before(:each) do
          module_class_load.valid?
        end

        context 'with metasploit_class' do
          let(:metasploit_class) do
            double('Msf::Module')
          end

          it { should_not include(error) }
        end

        context 'without metasploit_class' do
          let(:metasploit_class) do
            nil
          end

          it { should include(error) }
        end
      end
    end
  end

  context 'module_ancestor_partial_name' do
    subject(:module_ancestor_partial_name) do
      described_class.module_ancestor_partial_name(module_ancestor)
    end

    let(:module_ancestor) do
      FactoryGirl.create(:mdm_module_ancestor)
    end

    it { should start_with('RealPathSha1HexDigest') }

    it 'should include Metasploit::Model::Module::Ancestor#real_path_sha1_hex_digest' do
      module_ancestor_partial_name.should include(module_ancestor.real_path_sha1_hex_digest)
    end
  end
end
