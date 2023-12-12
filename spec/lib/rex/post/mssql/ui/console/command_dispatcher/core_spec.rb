# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/mssql/ui/console/command_dispatcher/core'

RSpec.describe Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Core do
  let(:rstream) { instance_double(::Rex::Socket) }
  let(:client) { instance_double(Rex::Proto::MSSQL::Client) }
  let(:session) { Msf::Sessions::MSSQL.new(nil, { client: client, cwd: 'mssql' }) }
  let(:address) { '192.0.2.1' }
  let(:port) { '1433' }
  let(:peer_info) { "#{address}:#{port}" }
  let(:console) do
    console = Rex::Post::MSSQL::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(client).to receive(:sock).and_return(rstream)
    allow(rstream).to receive(:peerinfo).and_return(peer_info)
    allow(session).to receive(:client).and_return(client)
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  it_behaves_like 'session command dispatcher'
end
