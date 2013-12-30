require 'spec_helper'

describe Metasploit::Framework::Command::Check::Help do
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
        dispatcher: dispatcher
    )
  end

  it_should_behave_like 'Metasploit::Framework::Command::Child'

  context '#run_with_valid' do
    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    #
    # lets
    #

    let(:full_name) do
      'module/class/full/name'
    end

    let(:option_parser) do
      parent.option_parser
    end

    #
    # Callbacks
    #

    before(:each) do
      dispatcher.stub_chain(:metasploit_instance, :full_name).and_return(full_name)
    end

    it 'should print help for option parser' do
      option_parser.should_receive(:help)

      quietly
    end

    it 'should include the metasploit_instance full name' do
      output.should include(full_name)
    end
  end
end