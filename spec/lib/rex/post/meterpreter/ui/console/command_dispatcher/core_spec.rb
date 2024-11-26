# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Core do
  let(:session) { instance_double(Msf::Sessions::Meterpreter) }
  # A meterpreter session *is* a client but for the smb session it *has* a (ruby smb) client
  let(:client) { session }
  let(:console) do
    console = Rex::Post::Meterpreter::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  it_behaves_like 'session command dispatcher'
end
