# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/smb/ui/console/command_dispatcher/core'

RSpec.describe Rex::Post::SMB::Ui::Console::CommandDispatcher::Core do
  let(:client) { instance_double(RubySMB::Client, dispatcher: dispatcher) }
  let(:simple_client) { instance_double(Rex::Proto::SMB::SimpleClient) }
  let(:dispatcher) { instance_double(RubySMB::Dispatcher::Socket, tcp_socket: socket) }
  let(:socket) { instance_double(IO) }
  let(:session) { Msf::Sessions::SMB.new(nil, { client: client }) }
  let(:console) do
    console = Rex::Post::SMB::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(Rex::Proto::SMB::SimpleClient).to receive(:new).and_return(simple_client)
    allow(session).to receive(:client).and_return(client)
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  it_behaves_like 'session command dispatcher'
end
