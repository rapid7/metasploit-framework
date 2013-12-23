require 'spec_helper'

describe Metasploit::Framework::Command::Use::SetMetasploitInstance do
  include_context 'Msf::Ui::Console::Driver'
  include_context 'output'

  subject(:command) do
    described_class.new(
        parent: parent
    )
  end

  let(:dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Core.new(msf_ui_console_driver)
  end

  let(:parent) do
    Metasploit::Framework::Command::Use.new(
        dispatcher: dispatcher,
        partial_word: partial_word,
        words: words
    )
  end

  let(:partial_word) do
    nil
  end

  let(:words) do
    []
  end

  it_should_behave_like 'Metasploit::Framework::Command::Child'
  it_should_behave_like 'Metasploit::Framework::Command::Use::SetMetasploitInstance::TabCompletion'

  context 'validations' do
    context 'metasploit_instance' do
      subject(:errors) do
        command.errors[:metasploit_instance]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!('errors.messages.blank')
      end

      #
      # Callbacks
      #

      before(:each) do
        command.stub(metasploit_instance: metasploit_instance)
        command.valid?
      end

      context 'with nil' do
        let(:metasploit_instance) do
          nil
        end

        it { should include error }
      end

      context 'without nil' do
        let(:metasploit_instance) do
          Msf::Module.new
        end

        it { should_not include error }
      end
    end

    context 'words' do
      subject(:errors) do
        command.errors[:words]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!(
            'metasploit.model.errors.models.metasploit/framework/command/use/set_metasploit_instance.attributes.words.wrong_length',
            count: 1
        )
      end

      #
      # Callbacks
      #

      before(:each) do
        command.valid?
      end

      context 'with 0' do
        let(:words) do
          []
        end

        it { should include error }
      end

      context 'with 1' do
        let(:words) do
          [
              'one'
          ]
        end

        it { should_not include error }
      end

      context 'with > 1' do
        let(:words) do
          [
              'one',
              'two'
          ]
        end

        it { should include error }
      end
    end
  end

  context '#metasploit_instance' do
    subject(:metasploit_instance) do
      command.metasploit_instance
    end

    it 'should be memoized' do
      expected = double('#metasploit_instance')
      command.instance_variable_set :@metasploit_instance, expected
      metasploit_instance.should == expected
    end

    context 'module_class_full_name' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      before(:each) do
        command.stub(module_class_full_name: module_class_full_name)
      end

      context 'with valid' do
        include_context 'metasploit_super_class_by_module_type'

        #
        # lets
        #

        let(:module_class) do
          FactoryGirl.create(
              :mdm_module_class,
              module_type: module_type
          )
        end

        let(:module_class_full_name) do
          module_class.full_name
        end

        let(:module_type) do
          Metasploit::Model::Module::Type::NON_PAYLOAD.sample
        end

        #
        # Callbacks
        #

        before(:each) do
          real_pathname = module_class.ancestors.first.real_pathname

          real_pathname.open('wb') do |f|
            f.puts "class Metasploit4 < #{metasploit_super_class}"
            f.puts "end"
          end
        end

        it { should be_a Msf::Module }
      end

      context 'without valid' do
        let(:module_class_full_name) do
          'invalid/module/class/full/name'
        end

        it { should be_nil }
      end
    end
  end

  context '#run_with_valid' do
    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    #
    # lets
    #

    let(:metasploit_instance) do
      double('#metasploit_instance')
    end

    #
    # Callbacks
    #

    before(:each) do
      command.stub(metasploit_instance: metasploit_instance)
    end

    it 'should set dispatcher.metasploit_instance' do
      command.metasploit_instance.should_not be_nil
      dispatcher.should_receive(:metasploit_instance=).with(command.metasploit_instance)

      run_with_valid
    end
  end
end