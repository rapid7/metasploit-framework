# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Core do
  let(:client) { instance_double(Msf::Sessions::Meterpreter) }
  let(:console) do
    console = Rex::Post::Meterpreter::Ui::Console.new(client)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(client).to receive(:console).and_return(console)
    allow(client).to receive(:name).and_return('test client name')
    allow(client).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(client.console) }

  it_behaves_like 'session command dispatcher'
end
