require 'spec_helper'

describe Metasploit::Framework::Command::Check::Simple do
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
    Metasploit::Framework::Command::Check.new(
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

  context 'validations' do
    context 'dispatcher' do
      subject(:dispatcher_errors) do
        command.errors[:dispatcher]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!('errors.messages.defanged')
      end

      #
      # Callbacks
      #

      before(:each) do
        msf_ui_console_driver.instance_variable_set :@defanged, defanged

        command.valid?
      end

      context 'with defanged' do
        let(:defanged) do
          true
        end

        it 'adds error on :dispatcher' do
          expect(dispatcher_errors).to include(error)
        end
      end

      context 'without defanged' do
        let(:defanged) do
          false
        end

        it 'does not add error on :dispatcher' do
          expect(dispatcher_errors).not_to include(error)
        end
      end
    end

    context 'metasploit_instance' do
      subject(:metasploit_instance_errors) do
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
        msf_ui_console_driver.metasploit_instance = metasploit_instance

        command.valid?
      end

      context 'with present' do
        let(:metasploit_instance) do
          Class.new(Msf::Module).new
        end

        it 'does not add error on :metasploit_instance' do
          expect(metasploit_instance_errors).not_to include(error)
        end
      end

      context 'without present' do
        let(:metasploit_instance) do
          nil
        end

        it 'adds error on :metasploit_instance' do
          expect(metasploit_instance_errors).to include(error)
        end
      end
    end

    context 'module_type' do
      subject(:module_type_errors) do
        command.errors[:module_type]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate('errors.messages.inclusion')
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(command).to receive(:module_type).and_return(module_type)

        command.valid?
      end

      context 'with exploit' do
        let(:module_type) do
          'exploit'
        end

        it 'does not add error on :module_type' do
          expect(module_type_errors).not_to include(error)
        end
      end

      context 'without exploit' do
        let(:module_type) do
          Metasploit::Model::Module::Type::ALL - ['exploit']
        end

        it 'adds error on :module_type' do
          expect(module_type_errors).to include(error)
        end
      end
    end

    context 'words' do
      subject(:words_errors) do
        command.errors[:words]
      end

      #
      # lets
      #

      let(:error) do
        I18n.translate!('errors.messages.wrong_length', count: 0)
      end

      #
      # Callbacks
      #

      before(:each) do
        command.valid?
      end

      context 'with words' do
        let(:words) do
          [
              'ignored',
              'words'
          ]
        end

        it 'adds error to :words' do
          expect(words_errors).to include(error)
        end
      end

      context 'without words' do
        let(:words) do
          []
        end

        it 'does not add error to :words' do
          expect(words_errors).not_to include(error)
        end
      end
    end
  end

  context '#metasploit_instance' do
    subject(:metasploit_instance) do
      command.metasploit_instance
    end

    context 'with #dispatcher' do
      #
      # lets
      #

      let(:dispatcher_metasploit_instance) do
        double('#dispatcher #metasploit_instance')
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(dispatcher).to receive(:metasploit_instance).and_return(dispatcher_metasploit_instance)
      end

      it 'delegates to #dispatcher' do
        expect(metasploit_instance).to be dispatcher_metasploit_instance
      end
    end

    context 'without #dispatcher' do
      let(:dispatcher) do
        nil
      end

      it { should be_nil }
    end
  end

  context '#module_type' do
    subject(:module_type) do
      command.module_type
    end

    before(:each) do
      allow(dispatcher).to receive(:metasploit_instance).and_return(metasploit_instance)
    end

    context 'with #metasploit_instance' do
      #
      # lets
      #

      let(:metasploit_instance) do
        double('#metasploit_instance')
      end

      let(:metasploit_instance_module_type) do
        FactoryGirl.generate :metasploit_model_module_type
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(metasploit_instance).to receive(:module_type).and_return(metasploit_instance_module_type)
      end

      it 'delegates to #metasploit_instance' do
        expect(module_type).to be metasploit_instance_module_type
      end
    end

    context 'without #metasploit_instance' do
      let(:metasploit_instance) do
        nil
      end

      it { should be_nil }
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
      allow(command).to receive(:metasploit_instance).and_return(metasploit_instance)
    end

    context 'with exception' do
      before(:each) do
        expect(metasploit_instance).to receive(:check_simple).and_raise(exception)
      end

      context 'Interrupt' do
        let(:exception_class) do
          Interrupt
        end

        let(:exception) do
          exception_class.new
        end

        it 'raises Interrupt so Ctrl+C can interrupt long running checks' do
          expect {
            run_with_valid
          }.to raise_error(exception_class)
        end
      end

      context 'Exception' do
        context 'with Msf::OptionValidateError' do
          let(:exception_class) do
            Msf::OptionValidateError
          end

          let(:exception) do
            exception_class.new(options)
          end

          let(:options) do
            Array.new(2) { |i|
              "invalid_option#{i}"
            }
          end

          it 'prints exception class' do
            expect(output).to include(exception_class.to_s)
          end

          it 'prints exception' do
            expect(output).to include(exception.to_s)
          end

          it 'does not print call stack' do
            expect(output).not_to include('Call stack')
          end
        end

        context 'without Msf::OptionValidateError' do
          let(:exception) do
            exception_class.new('message')
          end

          let(:exception_class) do
            Exception
          end

          it 'prints exception class' do
            expect(output).to include(exception_class.to_s)
          end

          it 'prints exception' do
            expect(output).to include(exception.to_s)
          end

          it 'prints call stack' do
            expect(output).to include('Call stack')
          end
        end
      end
    end

    context 'without exception' do
      before(:each) do
        expect(metasploit_instance).to receive(:check_simple).and_return(check_simple_return)
      end

      context 'with Msf::Exploit::CheckCode' do
        context 'with Msf::Exploit::CheckCode::Vulnerable' do
          let(:check_simple_return) do
            Msf::Exploit::CheckCode::Vulnerable
          end

          let(:message) do
            Msf::Exploit::CheckCode::Vulnerable[1]
          end

          it 'prints code as good' do
            expect(command).to receive(:print_good).with(message)

            quietly
          end
        end

        context 'without Msf::Exploit::CheckCode::Vulnerable' do
          let(:check_simple_return) do
            check_simple_returns.sample
          end

          let(:check_simple_returns) do
            [
                Msf::Exploit::CheckCode::Appears,
                Msf::Exploit::CheckCode::Detected,
                Msf::Exploit::CheckCode::Safe,
                Msf::Exploit::CheckCode::Unknown,
                Msf::Exploit::CheckCode::Unsupported
            ]
          end

          let(:message) do
            check_simple_return[1]
          end

          it 'prints code as status' do
            expect(command).to receive(:print_status).with(message)

            run_with_valid
          end
        end
      end

      context 'without Msf::Exploit::CheckCode' do
        let(:check_simple_return) do
          nil
        end

        it 'print state error' do
          expect(output).to include('Check failed: The state could not be determined.')
        end
      end
    end
  end
end