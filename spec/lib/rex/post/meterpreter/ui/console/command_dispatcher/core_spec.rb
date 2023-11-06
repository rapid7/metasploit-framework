# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/core'
require 'lib/msf/ui/console/command_dispatcher/session_spec'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Core do
  let(:client) do
    client = Msf::Sessions::Meterpreter.new(nil)
    client.interacting = true
    client
  end
  let(:shell) do
    console = Rex::Post::Meterpreter::Ui::Console.new(client)
    console.disable_output = true
    console
  end

  subject(:command_dispatcher) { described_class.new(shell) }

  it_behaves_like 'session command dispatcher'
end
