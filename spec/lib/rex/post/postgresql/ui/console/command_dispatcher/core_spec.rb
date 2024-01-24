# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/postgresql/ui/console'
require 'postgres/postgres-pr/connection'

RSpec.describe Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Core do
  let(:rstream) { instance_double(::Rex::Socket) }
  let(:client) { instance_double(Msf::Db::PostgresPR::Connection) }
  let(:address) { '192.0.2.1' }
  let(:port) { '5432' }
  let(:postgres_db) { 'template1' }
  let(:peer_info) { "#{address}:#{port}" }
  let(:session) { Msf::Sessions::PostgreSQL.new(nil, { client: client }) }
  let(:console) do
    console = Rex::Post::PostgreSQL::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(client).to receive(:conn).and_return(rstream)
    allow(client).to receive(:params).and_return({ 'database' => postgres_db })
    allow(rstream).to receive(:peerinfo).and_return(peer_info)
    allow(session).to receive(:client).and_return(client)
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  it_behaves_like 'session command dispatcher'
end
