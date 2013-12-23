require 'spec_helper'

describe Metasploit::Framework::Command::Use do
  include_context 'Msf::Ui::Console::Driver'

  subject(:command) do
    described_class.new(
        dispatcher: dispatcher,
        partial_word: partial_word,
        words: words
    )
  end

  #
  # lets
  #

  let(:dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Core.new(msf_ui_console_driver)
  end

  let(:partial_word) do
    nil
  end

  let(:words) do
    []
  end

  it_should_behave_like 'Metasploit::Framework::Command::Parent'

  context 'description' do
    subject(:description) do
      described_class.description
    end

    it { should == 'Selects a module by name' }
  end

  context 'subcommands' do
    it { should have_subcommand(:help).class_name('Metasploit::Framework::Command::Use::Help') }
    it { should have_subcommand(:set_metasploit_instance).class_name('Metasploit::Framework::Command::Use::SetMetasploitInstance').default(true) }
  end

  context '#option_parser' do
    subject(:option_parser) do
      command.option_parser
    end

    context 'banner' do
      subject(:banner) do
        option_parser.banner
      end

      it { should == 'Usage: use (-h|--help|MODULE_FULL_NAME)' }
    end
  end

  context '#parse_words' do
    subject(:parse_words) do
      command.send(:parse_words)
    end

    it 'should pass duplicate of #words to option_parser to parse' do
      command.option_parser.should_receive(:parse!) { |parsed_words|
        parsed_words.should_not be command.words
        parsed_words.should == command.words
      }.and_return([])

      parse_words
    end

    context 'words' do
      #
      # lets
      #

      let(:expected_module_class_full_name) do
        'module/class/full/name'
      end

      #
      # Callbacks
      #

      before(:each) do
        command.send(:parse_words)
      end

      context 'with 0' do
        let(:words) do
          []
        end

        context 'Metasploit::Framework::Command::Use::SetMetasploitInstance' do
          subject(:subcommand) do
            command.send(:subcommand_by_name)[:set_metasploit_instance]
          end

          context '#module_class_full_name' do
            subject(:module_class_full_name) do
              subcommand.module_class_full_name
            end

            it { should be_nil }
          end
        end
      end

      context 'with 1' do
        let(:words) do
          [
              expected_module_class_full_name
          ]
        end

        context 'Metasploit::Framework::Command::Use::SetMetasploitInstance' do
          subject(:subcommand) do
            command.send(:subcommand_by_name)[:set_metasploit_instance]
          end

          context '#module_class_full_name' do
            subject(:module_class_full_name) do
              subcommand.module_class_full_name
            end

            it 'should be the first non-option' do
              module_class_full_name.should == expected_module_class_full_name
            end
          end
        end
      end

      context 'with >1' do
        let(:words) do
          [
              expected_module_class_full_name,
              'extra/word'
          ]
        end

        context 'Metasploit::Framework::Command::Use::SetMetasploitInstance' do
          subject(:subcommand) do
            command.send(:subcommand_by_name)[:set_metasploit_instance]
          end

          context '#module_class_full_name' do
            subject(:module_class_full_name) do
              subcommand.module_class_full_name
            end

            it 'should be the first non-option' do
              module_class_full_name.should == expected_module_class_full_name
            end
          end
        end
      end
    end
  end
end