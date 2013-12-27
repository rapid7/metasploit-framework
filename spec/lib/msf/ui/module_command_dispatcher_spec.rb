require 'spec_helper'

describe Msf::Ui::Console::ModuleCommandDispatcher do
  include_context 'Msf::Ui::Console::Driver'

  subject(:command_dispatcher) do
    command_dispatcher_class.new(msf_ui_console_driver)
  end

  let(:command_dispatcher_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  it_should_behave_like 'Msf::Ui::Console::ModuleCommandDispatcher'

  context '#cmd_check' do
    subject(:cmd_check) do
      command_dispatcher.cmd_check
    end

    specify {
      expect {
        cmd_check
      }.to raise_error(NoMethodError)
    }
  end
end