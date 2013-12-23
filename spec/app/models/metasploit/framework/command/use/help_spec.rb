require 'spec_helper'

describe Metasploit::Framework::Command::Use::Help do
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
        dispatcher: dispatcher
    )
  end

  it_should_behave_like 'Metasploit::Framework::Command::Child'

  context '#run_with_valid' do
    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    let(:option_parser) do
      parent.option_parser
    end

    it 'shoud print help from option parser' do
      option_parser.should_receive(:help)

      quietly
    end
  end
end