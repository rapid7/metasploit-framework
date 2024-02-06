# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/mysql/ui/console'
require 'mysql'

RSpec.describe Rex::Post::MySQL::Ui::Console::CommandDispatcher::Core do
  let(:rstream) { instance_double(::Rex::Socket) }
  let(:client) { instance_double(::Mysql) }
  let(:database) { 'database_name' }
  let(:address) { '192.0.2.1' }
  let(:port) { '3306' }
  let(:peerinfo) { "#{address}:#{port}" }
  let(:session) { Msf::Sessions::MySQL.new(rstream, { client: client }) }
  let(:console) do
    console = Rex::Post::MySQL::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(rstream).to receive(:peerinfo).and_return(peerinfo)
    allow(client).to receive(:database).and_return(database)
    allow(client).to receive(:socket).and_return(rstream)
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  it_behaves_like 'session command dispatcher'
end
