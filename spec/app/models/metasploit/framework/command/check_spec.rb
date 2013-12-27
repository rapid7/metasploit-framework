require 'spec_helper'

describe Metasploit::Framework::Command::Check do
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

    it { should == 'Check to see if a target is vulnerable' }
  end

  context 'subcommands' do
    it { should have_subcommand(:help).class_name('Metasploit::Framework::Command::Check::Help') }
    it { should have_subcommand(:simple).class_name('Metasploit::Framework::Command::Check::Simple').default(true) }
  end

  context '#option_parser' do
    subject(:option_parser) do
      command.option_parser
    end

    context 'banner' do
      subject(:banner) do
        option_parser.banner
      end

      it { should == 'Usage: check [options]' }
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
  end
end