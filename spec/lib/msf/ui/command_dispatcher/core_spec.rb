require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/core'

describe Msf::Ui::Console::CommandDispatcher::Core do
	include_context 'Msf::DBManager'
	include_context 'Msf::Ui::Console::Driver'

	subject(:core) do
		described_class.new(msf_ui_console_driver)
  end

  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher' do
    let(:command_dispatcher) do
      core
    end
  end

  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::ReloadAll'
  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::Search'
  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::Spool'
  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::Threads'
end
